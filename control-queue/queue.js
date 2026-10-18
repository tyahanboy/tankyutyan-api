import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";

const DIR = new URL("./", import.meta.url);
const QUEUE_FILE = new URL("./queue.json", DIR);
const ALLOWED_ACTIONS = new Set([
  "start",
  "stop",
  "restart",
  "status"
]);

async function readQueue() {
  try {
    const data = await fs.readFile(QUEUE_FILE, "utf8");
    const queue = JSON.parse(data);
    return Array.isArray(queue) ? queue : [];
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function writeQueue(queue) {
  const temp = new URL("./queue.tmp", DIR);
  await fs.writeFile(temp, JSON.stringify(queue, null, 2), {
    mode: 0o600
  });
  await fs.rename(temp, QUEUE_FILE);
}

export async function enqueueAction(action, requestedBy) {
  if (!ALLOWED_ACTIONS.has(action)) {
    throw new Error("ACTION_NOT_ALLOWED");
  }

  const queue = await readQueue();
  const now = new Date();
  const item = {
    id: randomUUID(),
    action,
    requestedBy,
    status: "pending",
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 2 * 60 * 1000).toISOString()
  };

  queue.push(item);
  await writeQueue(queue);
  return item;
}

export async function listActions() {
  return readQueue();
}

export async function claimNextAction() {
  const queue = await readQueue();
  const now = Date.now();

  for (const item of queue) {
    if (item.status === "pending" &&
        Date.parse(item.expiresAt) <= now) {
      item.status = "expired";
    }
  }

  const item = queue.find(
    x => x.status === "pending" &&
         Date.parse(x.expiresAt) > now
  );

  if (!item) {
    await writeQueue(queue);
    return null;
  }

  item.status = "processing";
  item.claimedAt = new Date().toISOString();
  await writeQueue(queue);
  return item;
}

export async function finishAction(id, result) {
  const queue = await readQueue();
  const item = queue.find(x => x.id === id);

  if (!item || item.status !== "processing") {
    return false;
  }

  item.status = result?.ok === true ? "completed" : "failed";
  item.finishedAt = new Date().toISOString();
  item.result = {
    ok: result?.ok === true,
    message: String(result?.message || "").slice(0, 300)
  };

  await writeQueue(queue);
  return true;
}
