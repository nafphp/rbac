import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { chromium } from "playwright";

const stylesheet = await readFile(
  new URL("../../src/Resources/public/assets/rbac.css", import.meta.url),
  "utf8",
);

test("role controls honor motion and forced-color preferences", async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.setContent(
      "<style>" + stylesheet + "</style>" +
      '<details class="rbac-role">' +
      '<summary class="rbac-role-head">Editor<span class="rbac-role-caret" aria-hidden="true"></span></summary>' +
      '<label class="rbac-permission">' +
      '<input type="checkbox" role="switch" name="permissions[]" value="records.read">' +
      "<span>Read records</span></label></details>",
    );

    const summary = page.locator("summary");
    await summary.focus();
    await page.keyboard.press("Enter");
    assert.equal(await page.locator("details").evaluate((element) => element.open), true);

    const control = page.getByRole("switch", { name: "Read records" });
    await control.focus();
    await page.keyboard.press("Space");
    assert.equal(await control.isChecked(), true);
    assert.equal(await control.getAttribute("name"), "permissions[]");
    assert.equal(await page.locator(".rbac-role-caret").getAttribute("aria-hidden"), "true");

    await page.emulateMedia({ reducedMotion: "no-preference" });
    assert.equal(
      await control.evaluate((element) =>
        getComputedStyle(element).transitionDuration.split(",").some((value) => parseFloat(value) > 0),
      ),
      true,
    );

    await page.emulateMedia({ reducedMotion: "reduce" });
    for (const [locator, pseudo] of [
      [control, null],
      [control, "::before"],
      [page.locator(".rbac-role-caret"), null],
    ]) {
      assert.equal(
        await locator.evaluate(
          (element, pseudo) =>
            getComputedStyle(element, pseudo).transitionDuration.split(",").every((value) => parseFloat(value) === 0),
          pseudo,
        ),
        true,
      );
    }

    await page.emulateMedia({ forcedColors: "active" });
    assert.equal(await control.evaluate((element) => getComputedStyle(element).appearance), "auto");
    assert.equal(await control.evaluate((element) => getComputedStyle(element, "::before").display), "none");
  } finally {
    await browser.close();
  }
});
