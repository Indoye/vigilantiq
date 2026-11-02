import assert from "node:assert/strict";
import { test } from "node:test";
import { isPersonalDomain } from "./emailpolicy.ts";

test("adresses professionnelles et personnelles", () => {
  for (const d of ["gmail.com", "yahoo.fr", "hotmail.com", "outlook.fr", "icloud.com", "proton.me", "mailinator.com", "orange.sn", "sunumail.sn", "yopmail.com"]) assert.ok(isPersonalDomain(d), d);
  for (const d of ["entreprise.sn", "mail.entreprise.sn", "sonatel.com", "orange-sonatel.com", "orange.com", "gouv.sn", "ucad.edu.sn", "wave.com"]) assert.ok(!isPersonalDomain(d), d);
});
