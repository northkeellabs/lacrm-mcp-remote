// The 10 LACRM tools. Names, inputs and output shapes match lacrm_mcp/server.py.

import { McpServer, type CallToolResult } from "@modelcontextprotocol/server";
import { z } from "zod";
import { LacrmClient, LacrmError } from "./lacrm";
import { DATA_NOTICE, sanitize } from "./security";

export const SCOPE_READ = "lacrm.read";
export const SCOPE_WRITE = "lacrm.write";

export const READ_TOOLS = [
  "search_contacts",
  "get_contact",
  "list_contact_notes",
  "list_tasks",
  "list_pipelines",
  "list_pipeline_items",
] as const;
export const WRITE_TOOLS = ["create_contact", "add_note", "create_task", "update_pipeline_item_status"] as const;

export const SERVER_VERSION = "0.1.0";

export class ToolError extends Error {}

// LACRM ids ("Uid") are ~31-digit numbers that must be handled as strings.
const Uid = z.string().regex(/^\d{1,40}$/).describe("LACRM record id (digits only, passed as a string)");
const MaxResults = z.number().int().min(1).max(50).default(20).describe("Results per page (1-50)");
const PageNo = z.number().int().min(1).max(1000).default(1).describe("Page number, starting at 1");
const IsoDate = z.iso.date();

const READ = { readOnlyHint: true, openWorldHint: false };
const WRITE = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };

type Rec = Record<string, any>;
const isRec = (v: unknown): v is Rec => v !== null && typeof v === "object" && !Array.isArray(v);
const results = (data: any): Rec[] => (isRec(data) && Array.isArray(data.Results) ? data.Results.filter(isRec) : []);

function displayName(rec: Rec): string {
  const name = rec.Name;
  if (isRec(name)) {
    return ["Salutation", "FirstName", "MiddleName", "LastName", "Suffix"]
      .map((k) => name[k])
      .filter((p) => p)
      .join(" ");
  }
  return name || rec["Company Name"] || "";
}

function firstText(items: unknown): string | null {
  if (Array.isArray(items) && items.length && isRec(items[0])) return items[0].Text ?? null;
  return null;
}

const g = (rec: Rec, k: string) => (k in rec ? rec[k] : null);

function contactSummary(rec: Rec): Rec {
  return {
    contact_id: g(rec, "ContactId"),
    is_company: g(rec, "IsCompany"),
    name: displayName(rec),
    company_name: !rec.IsCompany ? g(rec, "Company Name") : null,
    job_title: g(rec, "Job Title"),
    email: firstText(rec.Email),
    phone: firstText(rec.Phone),
    assigned_to: g(rec, "AssignedTo"),
    last_update: g(rec, "LastUpdate"),
  };
}

function wrap(list: Rec[], hasMore: unknown, page: number): unknown {
  return sanitize({ data_notice: DATA_NOTICE, page, has_more_results: Boolean(hasMore), count: list.length, results: list });
}

function ok(value: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value as Rec };
}

function fail(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

export interface ToolContext {
  client: LacrmClient;
  scopes: readonly string[];
  /** LACRM user id captured at consent time; used as the default owner for create_contact. */
  userId?: string;
  log?: (msg: string) => void;
}

export function canWrite(scopes: readonly string[]): boolean {
  return scopes.includes(SCOPE_WRITE);
}

/** Build a fresh McpServer for one request. Write tools are only registered for write grants. */
export function buildServer(ctx: ToolContext): McpServer {
  const writable = canWrite(ctx.scopes);
  const server = new McpServer(
    { name: "lacrm", version: SERVER_VERSION },
    {
      instructions:
        "Unofficial tools for reading and updating a Less Annoying CRM account." +
        (writable ? "" : " This server is in read-only mode."),
    },
  );
  const { client } = ctx;

  function tool<S extends z.ZodObject>(
    name: string,
    description: string,
    inputSchema: S,
    run: (args: z.infer<S>) => Promise<unknown>,
    write = false,
  ) {
    if (write && !writable) return; // not even listed
    server.registerTool(
      name,
      { description, inputSchema, annotations: write ? WRITE : READ },
      (async (args: z.infer<S>) => {
        // Enforced on every call, independent of registration.
        if (write && !canWrite(ctx.scopes)) return fail("This grant is read-only; write tools are disabled.");
        try {
          return ok(await run(args));
        } catch (exc) {
          if (exc instanceof ToolError) return fail(exc.message);
          if (exc instanceof LacrmError) return fail(client.clean(exc.message));
          ctx.log?.(`unexpected error in ${name}: ${exc instanceof Error ? exc.name : "Error"}`);
          return fail(`Unexpected error (${exc instanceof Error ? exc.name : "Error"}).`);
        }
      }) as any,
    );
  }

  const defaultUser = async (): Promise<string> => {
    if (ctx.userId) return ctx.userId;
    const user = await client.call("GetUser");
    return String(user.UserId);
  };

  // ------------------------------------------------------------- read tools

  tool(
    "search_contacts",
    "Search Less Annoying CRM contacts and companies by text (calls GetContacts). Returns a short summary per record (id, name, company, title, first email and phone, owner, last update), paged, at most 50 per page. Use get_contact for full details.",
    z.object({
      query: z.string().max(200).optional().describe("Text to search for in contact/company fields. Omit to list recent records."),
      record_type: z.enum(["Contacts", "Companies"]).optional().describe("Restrict to people or companies"),
      sort_by: z.enum(["Relevance", "FirstName", "LastName", "CompanyName", "DateCreated", "LastUpdate"]).default("Relevance"),
      max_results: MaxResults,
      page: PageNo,
    }),
    async (a) => {
      const params: Rec = { SortBy: a.sort_by, SortDirection: "Descending", MaxNumberOfResults: a.max_results, Page: a.page };
      if (a.query) params.SearchTerms = a.query;
      if (a.record_type) params.RecordTypeFilter = a.record_type;
      const data = await client.call("GetContacts", params);
      return wrap(results(data).map(contactSummary), data?.HasMoreResults, a.page);
    },
  );

  tool(
    "get_contact",
    "Get the full record for one contact or company by id (calls GetContact), including emails, phones, addresses, websites and background info. Text fields are truncated at 2000 characters.",
    z.object({ contact_id: Uid }),
    async (a) => {
      const data = await client.call("GetContact", { ContactId: a.contact_id });
      return sanitize({ data_notice: DATA_NOTICE, contact: data });
    },
  );

  tool(
    "list_contact_notes",
    "List the notes attached to a contact or company (calls GetNotesAttachedToContact): note id, text, author user id and the date shown in the contact history. Paged, at most 50 per page.",
    z.object({ contact_id: Uid, max_results: MaxResults, page: PageNo }),
    async (a) => {
      const data = await client.call("GetNotesAttachedToContact", {
        ContactId: a.contact_id,
        MaxNumberOfResults: a.max_results,
        Page: a.page,
      });
      const list = results(data).map((n) => ({
        note_id: g(n, "NoteId"),
        date: g(n, "DateDisplayedInHistory"),
        user_id: g(n, "UserId"),
        note: g(n, "Note"),
      }));
      return wrap(list, data?.HasMoreResults, a.page);
    },
  );

  tool(
    "list_tasks",
    "List tasks due within a date range (calls GetTasks), optionally filtered by completion status or by a contact. Returns task id, name, due date, assignee and description. Paged, at most 50 per page.",
    z.object({
      start_date: IsoDate.describe("Earliest task date, YYYY-MM-DD"),
      end_date: IsoDate.describe("Latest task date, YYYY-MM-DD"),
      completion_status: z.enum(["Both", "Incomplete", "Complete"]).default("Incomplete"),
      contact_id: Uid.optional().describe("Only tasks attached to this contact"),
      max_results: MaxResults,
      page: PageNo,
    }),
    async (a) => {
      const start = Date.parse(`${a.start_date}T00:00:00Z`);
      const end = Date.parse(`${a.end_date}T00:00:00Z`);
      if (end < start) throw new ToolError("end_date must not be before start_date.");
      if ((end - start) / 86_400_000 > 366) throw new ToolError("Date range may not exceed 366 days.");
      const params: Rec = {
        StartDate: a.start_date,
        EndDate: a.end_date,
        CompletionStatus: a.completion_status,
        MaxNumberOfResults: a.max_results,
        Page: a.page,
      };
      if (a.contact_id) params.ContactId = a.contact_id;
      const data = await client.call("GetTasks", params);
      const fields: [string, string][] = [
        ["task_id", "TaskId"],
        ["name", "Name"],
        ["due_date", "DueDate"],
        ["assigned_to", "AssignedTo"],
        ["description", "Description"],
        ["contact_id", "ContactId"],
        ["is_complete", "IsComplete"],
      ];
      const list = results(data).map((t) => {
        const out: Rec = {};
        for (const [k, src] of fields) if (src in t) out[k] = t[src];
        return out;
      });
      return wrap(list, data?.HasMoreResults, a.page);
    },
  );

  tool(
    "list_pipelines",
    "List the account's pipelines and their statuses (calls GetPipelines, without custom field definitions). Use it to find the pipeline and status ids needed by list_pipeline_items and update_pipeline_item_status.",
    z.object({}),
    async () => {
      const data = await client.call("GetPipelines", { IncludeCustomFields: false });
      const pipelines = (Array.isArray(data) ? data.filter(isRec) : []).map((p) => ({
        pipeline_id: g(p, "PipelineId"),
        name: g(p, "Name"),
        statuses: (Array.isArray(p.Statuses) ? p.Statuses.filter(isRec) : []).map((s: Rec) => ({
          status_id: g(s, "StatusId"),
          name: g(s, "Name"),
          is_active: g(s, "IsActive"),
        })),
      }));
      return sanitize({ data_notice: DATA_NOTICE, pipelines });
    },
  );

  tool(
    "list_pipeline_items",
    "List items in one pipeline (calls GetPipelineItems), optionally limited to certain statuses. Returns item id, contact id and name, status, last update and last note. Paged, at most 50 per page.",
    z.object({
      pipeline_id: Uid,
      status_ids: z.array(Uid).max(20).optional().describe("Only items in these statuses; omit for all active statuses"),
      sort_by: z.enum(["Status", "DateCreated", "LastUpdate"]).default("Status"),
      max_results: MaxResults,
      page: PageNo,
    }),
    async (a) => {
      const params: Rec = { PipelineId: a.pipeline_id, SortBy: a.sort_by, MaxNumberOfResults: a.max_results, Page: a.page };
      if (a.status_ids && a.status_ids.length) params.StatusFilter = a.status_ids;
      const data = await client.call("GetPipelineItems", params);
      const list = results(data).map((i) => ({
        pipeline_item_id: g(i, "PipelineItemId"),
        contact_id: g(i, "ContactId"),
        contact_name: isRec(i.ContactMetaData) ? g(i.ContactMetaData, "Name") : null,
        pipeline: isRec(i.PipelineMetaData) ? g(i.PipelineMetaData, "Name") : null,
        status_id: g(i, "StatusId"),
        status: isRec(i.StatusMetaData) ? g(i.StatusMetaData, "Name") : null,
        last_update: g(i, "LastUpdate"),
        last_note: g(i, "LastNote"),
      }));
      return wrap(list, data?.HasMoreResults, a.page);
    },
  );

  // ------------------------------------------------------------ write tools

  tool(
    "create_contact",
    "Create a new contact or company (calls CreateContact). Does not check for duplicates. Returns the new contact id.",
    z.object({
      name: z.string().min(1).max(200).describe("Full name of the person, or the company name"),
      is_company: z.boolean().default(false).describe("True to create a company record"),
      email: z.string().max(254).regex(/^[^@\s]+@[^@\s]+\.[^@\s]+$/).optional(),
      phone: z.string().max(40).optional(),
      company_name: z.string().max(200).optional().describe("Employer; linked or created if missing. Ignored for companies."),
      job_title: z.string().max(200).optional(),
      background_info: z.string().max(5000).optional(),
      assigned_to: Uid.optional().describe("User id to own the record; defaults to the API key's user"),
    }),
    async (a) => {
      const owner = a.assigned_to || (await defaultUser());
      const params: Rec = { IsCompany: a.is_company, AssignedTo: owner };
      params[a.is_company ? "Company Name" : "Name"] = a.name;
      if (a.email) params.Email = [{ Text: a.email }];
      if (a.phone) params.Phone = [{ Text: a.phone }];
      if (a.company_name && !a.is_company) params["Company Name"] = a.company_name;
      if (a.job_title && !a.is_company) params["Job Title"] = a.job_title;
      if (a.background_info) params["Background Info"] = a.background_info;
      const data = await client.call("CreateContact", params, false);
      return { contact_id: data?.ContactId ?? null };
    },
    true,
  );

  tool(
    "add_note",
    "Attach a plain-text note to an existing contact or company (calls CreateNote), timestamped now. Returns the new note id.",
    z.object({ contact_id: Uid, note: z.string().min(1).max(5000) }),
    async (a) => {
      const data = await client.call("CreateNote", { ContactId: a.contact_id, Note: a.note }, false);
      return { note_id: data?.NoteId ?? null };
    },
    true,
  );

  tool(
    "create_task",
    "Create a task (calls CreateTask), optionally attached to a contact. Returns the new task id.",
    z.object({
      name: z.string().min(1).max(200),
      due_date: IsoDate.optional().describe("YYYY-MM-DD"),
      description: z.string().max(5000).optional(),
      contact_id: Uid.optional().describe("Attach the task to this contact"),
      assigned_to: Uid.optional().describe("User id; LACRM defaults to the API key's user"),
    }),
    async (a) => {
      const params: Rec = { Name: a.name };
      if (a.due_date) params.DueDate = a.due_date;
      if (a.description) params.Description = a.description;
      if (a.contact_id) params.ContactId = a.contact_id;
      if (a.assigned_to) params.AssignedTo = a.assigned_to;
      const data = await client.call("CreateTask", params, false);
      return { task_id: data?.TaskId ?? null };
    },
    true,
  );

  tool(
    "update_pipeline_item_status",
    "Move a pipeline item to another status (calls EditPipelineItem). Status automations are explicitly not run. Returns a confirmation.",
    z.object({
      pipeline_item_id: Uid,
      status_id: Uid.describe("Target status id (see list_pipelines)"),
      note: z.string().max(2000).optional().describe("Optional note recorded in the item's history"),
    }),
    async (a) => {
      const params: Rec = { PipelineItemId: a.pipeline_item_id, StatusId: a.status_id, RunStatusAutomation: false };
      if (a.note) params.Note = a.note;
      await client.call("EditPipelineItem", params, false);
      return { ok: true, pipeline_item_id: a.pipeline_item_id, status_id: a.status_id };
    },
    true,
  );

  return server;
}
