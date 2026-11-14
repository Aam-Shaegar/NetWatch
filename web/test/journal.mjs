import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright-core";
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  const page = await browser.newPage();
  await page.goto(process.env.NETWATCH_UI_URL);
  await page.keyboard.press("Tab");
  assert.equal(await page.locator(":focus").getAttribute("name"), "token");
  await page.keyboard.type(process.env.NETWATCH_UI_TEST_TOKEN);
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  const card = page
    .getByRole("button", {
      name: new RegExp("^Инцидент №" + process.env.NETWATCH_UI_ID + " ·"),
    })
    .first();
  await card.waitFor();
  // Navigate from the first filter through the journal using the keyboard.
  await page.getByLabel("Объект", { exact: true }).focus();
  for (
    let i = 0;
    i < 40 && !(await card.evaluate((el) => el === document.activeElement));
    i++
  )
    await page.keyboard.press("Tab");
  assert(await card.evaluate((el) => el === document.activeElement));
  await page.keyboard.press("Enter");
  await page.getByRole("table").waitFor();
  const ack = page.getByRole("button", { name: "Подтвердить просмотр" });
  await ack.focus();
  await page.keyboard.press("Enter");
  await page.getByText("acceptance", { exact: true }).waitFor();
  const promise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Скачать JSON" }).click();
  const download = await promise;
  const data = JSON.parse(await readFile(await download.path(), "utf8"));
  assert.equal(data.incident.ack_by, "acceptance");
  assert(data.events.some((e) => e.kind === "opened"));
  assert(data.events.some((e) => e.kind === "closed"));
  assert(data.events.some((e) => e.prediction.score > e.prediction.threshold));
  assert(data.events.every((e) => Number.isFinite(e.features.in_packets)));
  await page.getByLabel("Объект", { exact: true }).fill("missing");
  await page.getByRole("button", { name: "Применить" }).click();
  await page.getByText("Инцидентов по этому запросу нет.").waitFor();
  for (const retrying of [false, true]) {
    await page.route("**/v1/incidents?**", (route) =>
      route.fulfill({
        json: { incidents: [], next: "", pending: true, retrying },
      }),
    );
    await page.getByRole("button", { name: "Обновить" }).click();
    await page
      .getByText(retrying ? /Обработка задержана/ : /ещё не обработаны/)
      .waitFor();
    await page.unroute("**/v1/incidents?**");
  }
  await page.route("**/v1/incidents?**", (route) =>
    route.fulfill({ status: 503, body: "{}" }),
  );
  await page.getByRole("button", { name: "Обновить" }).click();
  await page.getByRole("alert").waitFor();
  console.log(
    "Browser verified keyboard, evidence, acknowledgement, export, empty and error states.",
  );
} finally {
  await browser.close();
}
