import assert from "node:assert/strict";
import { test } from "node:test";
import { byDeadline, countdown, deadlineOf, levelOf, makeDeadline } from "./deadlines.ts";

const NOW = Date.parse("2026-11-02T09:00:00Z");

test("échéance CISA prioritaire sur le délai recommandé", () => {
  const d = deadlineOf({ priority: "basse", published: "2026-11-01T00:00:00Z", kev: { dueDate: "2026-11-05" } }, NOW)!;
  assert.deepEqual(d, { date: "2026-11-05", source: "cisa", daysLeft: 3, level: "proche" });
});

test("délai recommandé compté depuis la publication", () => {
  assert.equal(deadlineOf({ priority: "urgente", published: "2026-11-01T20:00:00Z" }, NOW)!.date, "2026-11-03");
  assert.equal(deadlineOf({ priority: "haute", published: "2026-10-20T00:00:00Z" }, NOW)!.daysLeft, -6);
  assert.equal(deadlineOf({ priority: "haute", published: "pas une date" }, NOW), null);
});

test("niveaux, compte à rebours et tri", () => {
  assert.deepEqual([-1, 0, 2, 3, 7, 8, 14, 15].map(levelOf), ["retard", "urgent", "urgent", "proche", "proche", "bientot", "bientot", "plus-tard"]);
  assert.deepEqual([-4, -1, 0, 1, 9].map((n) => countdown(makeDeadline(new Date(NOW + n * 86400_000).toISOString(), "cisa", NOW)!)), [
    "En retard de 4 j",
    "En retard d’1 j",
    "Aujourd’hui",
    "Demain",
    "Dans 9 j",
  ]);
  const a = makeDeadline("2026-11-04", "priorite", NOW);
  const b = makeDeadline("2026-11-04", "cisa", NOW);
  const c = makeDeadline("2026-10-30", "priorite", NOW);
  assert.deepEqual([a, b, null, c].sort(byDeadline).map((x) => x && `${x.date}:${x.source}`), ["2026-10-30:priorite", "2026-11-04:cisa", "2026-11-04:priorite", null]);
});

test("échéances : un retard seulement si l'organisation est engagée", async () => {
  const { isOverdue, refLabel, makeDeadline } = await import("./deadlines.ts");
  const now = Date.parse("2026-11-09T12:00:00Z");
  const past = makeDeadline("2026-11-06", "cisa", now)!;
  assert.equal(isOverdue(past, false), false);
  assert.equal(isOverdue(past, true), true);
  assert.equal(isOverdue(makeDeadline("2026-11-12", "priorite", now), true), false);
  assert.equal(refLabel(past), "Échéance CISA : 6 nov.");
  assert.equal(refLabel(makeDeadline("2026-11-06", "priorite", now)!), "Délai conseillé : 6 nov.");
});
