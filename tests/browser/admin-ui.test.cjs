/* Browser regression tests use only fictional robots and stubbed local API responses. */
const {test, before, after, beforeEach, afterEach} = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const {chromium} = require("playwright");

const assetDir = path.resolve(__dirname, "../../src/roborock_local_server/admin_ui");
const fixtureDir = path.resolve(__dirname, "artifacts/fixtures");
const outputDir = path.resolve(__dirname, "artifacts");
let server, browser, context, page, baseURL, state;

function fixtures() {
  return {
    loggedIn: true,
    fail: new Set(),
    requests: [],
    scheduleConflict: false,
    timerFailure: false,
    unverifiedTimerResponse: false,
    timerDelay: 0,
    resetDelay: 0,
    roomConflict: false,
    roomCatalog: {revision: "downstairs-rooms-v1", map_index: 0, maps: [{id: 0, name: "Downstairs"}, {id: 1, name: "Upstairs"}],
      rooms: [{id: 16, room_id: "cloud-kitchen", name: "Kitchen"}, {id: 17, room_id: "cloud-hall", name: "Hall"}, {id: 18, room_id: "cloud-office", name: "Office"}]},
    schedules: {
      supported: true, generated_at: "2026-10-24T16:00:00Z", server_timezone: "America/Los_Angeles",
      devices: [
        {duid: "sample-downstairs", name: "Downstairs", model: "roborock.vacuum.a15", connected: true, schedules: [
          {id: 42, revision: "revision-42", cron: "30 9 * * 1-5", timeZoneId: "America/Los_Angeles", enabled: true, repeated: true,
            next_run_at: "2026-10-26T16:30:00Z", native_timer_name: "native-kitchen", native_timer_state: "not_checked", editable: true,
            settings_editable: true,
            setting_choices: {fan_power: [{value: 101, label: "Quiet"}, {value: 102, label: "Balanced"}, {value: 103, label: "Turbo"}, {value: 104, label: "Max"}, {value: 105, label: "Off / mop only"}, {value: 106, label: "Room settings"}],
              water_box_mode: [{value: 200, label: "Off"}, {value: 201, label: "Low"}, {value: 202, label: "Medium"}, {value: 203, label: "High"}, {value: 204, label: "Room settings"}],
              mop_mode: [{value: 300, label: "Standard"}, {value: 301, label: "Deep"}, {value: 302, label: "Room settings"}], repeat: [{value: 1, label: "1 pass"}, {value: 2, label: "2 passes"}, {value: 3, label: "3 passes"}]},
            settings: {map_index: 0, segments: "16,17", fan_power: 102, water_box_mode: 202, mop_mode: 300, repeat: 1, clean_order_mode: 1, mop_template_id: 4, clean_mop: 1}},
          {id: 43, revision: "revision-43", cron: "0,30 8-9 * * *", timeZoneId: "Europe/Berlin", enabled: false, repeated: true,
            next_run_at: null, native_timer_name: null, native_timer_state: null, settings: {}, editable: true},
          {id: 44, revision: "revision-44", cron: "0 10 26 10 *", timeZoneId: "America/Los_Angeles", enabled: true, repeated: false,
            next_run_at: "2026-10-26T17:00:00Z", native_timer_name: "native-once", native_timer_state: "not_checked", settings: {}, editable: true},
        ]},
        {duid: "sample-upstairs", name: "Upstairs", model: "roborock.vacuum.a27", connected: false, schedules: [
          {id: 42, revision: "upstairs-revision-42", cron: "0 11 * * *", timeZoneId: "America/Los_Angeles", enabled: true, repeated: true,
            next_run_at: "2026-10-24T18:00:00Z", native_timer_name: "native-office", native_timer_state: "not_checked", settings: {map_index: 1}, editable: true},
        ]},
      ],
    },
    auth: {
      new_connections_enabled: true, admin_session_secret: "fictional-sync-secret",
      protocol_session_count: 1, pending_device_mqtt_recovery: [],
      protocol_sessions: [{rruid: "LocalRock", hawk_id: "sample-id", hawk_session: "sample-session", source: "app_login", updated_at_utc: "2026-10-23T18:00:00Z"}],
    },
    health: {overall_ok: true, services: [
      {name: "https_server", running: true, enabled: true, required: true},
      {name: "mqtt_proxy", running: true, enabled: true, required: true},
      {name: "mqtt_broker", running: true, enabled: true, required: true},
      {name: "topic_bridge", running: true, enabled: true, required: true},
      {name: "turn_relay", running: false, enabled: false, required: false},
    ]},
    vacuums: [
      {duid: "sample-downstairs", name: "Downstairs", model: "roborock.vacuum.a15", connected: true, mqtt_credentials: {saved: true, cleared_at: ""}, onboarding: {has_public_key: true, key_state: {query_samples: 4}}},
      {duid: "sample-upstairs", name: "Upstairs", model: "roborock.vacuum.a27", connected: false, mqtt_credentials: {saved: false, cleared_at: ""}, onboarding: {has_public_key: false, key_state: {query_samples: 0}}},
    ],
  };
}

async function serve(req, res) {
  const url = new URL(req.url, baseURL || "http://localhost");
  const reply = (data, status = 200) => {
    res.writeHead(status, {"Content-Type": "application/json"});
    res.end(JSON.stringify(data));
  };
  if (url.pathname === "/admin") {
    const html = await fs.readFile(path.join(fixtureDir, state.loggedIn ? "dashboard.html" : "login.html"), "utf8");
    res.writeHead(200, {"Content-Type": "text/html"});
    res.end(html);
    return;
  }
  if (url.pathname === "/admin/static/style.css") {
    res.writeHead(200, {"Content-Type": "text/css"});
    res.end(await fs.readFile(path.join(fixtureDir, "style.css")));
    return;
  }
  if (url.pathname.startsWith("/admin/assets/")) {
    const name = url.pathname.split("/").pop();
    if (!["schedules.css", "schedules.js"].includes(name)) return reply({}, 404);
    res.writeHead(200, {"Content-Type": name.endsWith(".css") ? "text/css" : "text/javascript"});
    res.end(await fs.readFile(path.join(assetDir, name)));
    return;
  }
  if (url.pathname === "/test-icons.woff2") {
    res.writeHead(200, {"Content-Type": "font/woff2"});
    res.end(await fs.readFile(path.join(fixtureDir, "material-icons.woff2")));
    return;
  }
  if (url.pathname === "/favicon.ico") { res.writeHead(204); res.end(); return; }
  if (!url.pathname.startsWith("/admin/api/")) return reply({}, 404);
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
  state.requests.push({path: url.pathname, method: req.method, body});
  if (state.fail.has(url.pathname)) return reply({error: "Simulated server failure"}, 503);
  if (url.pathname === "/admin/api/login") {
    if (body.password !== "test-password") return reply({error: "Invalid password"}, 401);
    state.loggedIn = true;
    return reply({ok: true});
  }
  if (!state.loggedIn) return reply({error: "Authentication required"}, 401);
  const credentialPath = /^\/admin\/api\/vacuums\/([^/]+)\/mqtt-credentials$/.exec(url.pathname);
  if (credentialPath && req.method === "DELETE") {
    const vacuum = state.vacuums.find((item) => item.duid === decodeURIComponent(credentialPath[1]));
    if (!vacuum) return reply({error: "Vacuum not found"}, 404);
    if (state.resetDelay) await new Promise((resolve) => setTimeout(resolve, state.resetDelay));
    vacuum.mqtt_credentials = {saved: false, cleared_at: "2026-10-25T00:00:00Z"};
    vacuum.connected = false;
    return reply({ok: true, duid: vacuum.duid, name: vacuum.name, mqtt_credentials: vacuum.mqtt_credentials});
  }
  const schedulePath = /^\/admin\/api\/schedules\/([^/]+)\/([^/]+)$/.exec(url.pathname);
  if (schedulePath && schedulePath[2] === "rooms" && req.method === "GET") return reply(state.roomCatalog);
  if (schedulePath && schedulePath[2] === "rooms" && req.method === "POST") {
    state.roomCatalog.map_index = body.map_index;
    state.roomCatalog.revision = "upstairs-rooms-v1";
    state.roomCatalog.rooms = [{id: 25, room_id: "bedroom", name: "Bedroom"}];
    return reply(state.roomCatalog);
  }
  if (schedulePath && req.method === "PATCH") {
    const device = state.schedules.devices.find((item) => item.duid === decodeURIComponent(schedulePath[1]));
    const job = device?.schedules.find((item) => String(item.id) === decodeURIComponent(schedulePath[2]));
    if (!job) return reply({error: "Schedule not found"}, 404);
    if (state.scheduleConflict || body.revision !== job.revision) return reply({error: "Schedule changed. Reload the saved values before editing."}, 409);
    if (state.roomConflict && body.settings?.segments) return reply({error: "The map or room list changed. Refresh rooms and review your selection before saving.", code: "room_catalog_changed"}, 409);
    if (Object.hasOwn(body, "enabled") && job.native_timer_name) {
      if (state.timerDelay) await new Promise((resolve) => setTimeout(resolve, state.timerDelay));
      if (state.timerFailure) return reply({error: "The vacuum did not confirm the requested timer setting. Refresh schedules and retry.", code: "timer_sync_failed"}, 503);
      job.native_timer_state = state.unverifiedTimerResponse ? "not_checked" : body.enabled ? "on" : "off";
    }
    for (const key of ["cron", "timeZoneId", "enabled", "repeated"]) if (Object.hasOwn(body, key)) job[key] = body[key];
    if (body.settings) Object.assign(job.settings, body.settings);
    job.revision += "-saved";
    return reply({schedule: job});
  }
  switch (url.pathname) {
    case "/admin/api/activity": return reply({raw: false, entries: [
      {time: "16:00:00", source: "mqtt", direction: "in", topic: url.searchParams.get("device"), rpc_methods: ["get_status"]},
    ]});
    case "/admin/api/status": return reply({health: state.health});
    case "/admin/api/vacuums": return reply({vacuums: state.vacuums});
    case "/admin/api/schedules": return reply(state.schedules);
    case "/admin/api/auth":
      if (req.method === "POST") state.auth.new_connections_enabled = body.new_connections_enabled;
      return reply(state.auth);
    case "/admin/api/cloud/request-code": return reply({session_id: "test-cloud-session", success: true});
    case "/admin/api/cloud/submit-code":
      if (body.session_id !== "test-cloud-session" || body.code !== "123456") return reply({error: "Invalid verification code"}, 400);
      return reply({success: true, device_count: state.vacuums.length});
    case "/admin/api/auth/sessions/sample-id/sample-session":
      if (req.method !== "DELETE") return reply({}, 405);
      state.auth.protocol_sessions = [];
      state.auth.protocol_session_count = 0;
      return reply({ok: true, auth: state.auth});
    case "/admin/api/logout": state.loggedIn = false; return reply({ok: true});
    default: return reply({}, 404);
  }
}

test("MQTT recovery clears only the chosen vacuum after confirmation", async () => {
  await ready();
  const button = page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true});
  assert.equal(await page.getByRole("button", {name: "Clear MQTT credentials for Upstairs", exact: true}).count(), 0);
  page.once("dialog", (dialog) => dialog.dismiss());
  await button.click();
  assert.equal(state.requests.filter((item) => item.path.endsWith("/mqtt-credentials")).length, 0);
  page.once("dialog", (dialog) => {
    assert.match(dialog.message(), /Downstairs/);
    return dialog.accept();
  });
  await button.click();
  await page.waitForFunction(() => document.querySelector("#credentialList").textContent.includes("Credentials cleared for Downstairs"));
  assert.equal(await button.isDisabled(), true);
  assert.equal(state.auth.protocol_sessions.length, 1);
  assert.equal(state.requests.filter((item) => item.method === "DELETE").length, 1);
  assert.equal(state.requests.find((item) => item.method === "DELETE").path, "/admin/api/vacuums/sample-downstairs/mqtt-credentials");
  assert.match(await page.locator("#credentialList").textContent(), /Add vacuum in LocalRock/);
  await page.setViewportSize({width: 320, height: 900});
  await noOverflow();
});

test("credential reset failures keep the action available for retry", async () => {
  state.fail.add("/admin/api/vacuums/sample-downstairs/mqtt-credentials");
  await ready();
  page.once("dialog", (dialog) => dialog.accept());
  const button = page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true});
  await button.click();
  await page.waitForFunction(() => document.querySelector("#credentialList").textContent.includes("Simulated server failure"));
  assert.equal(await button.isEnabled(), true);
  assert.equal(state.vacuums[0].mqtt_credentials.saved, true);
});

before(async () => {
  await fs.mkdir(outputDir, {recursive: true});
  server = http.createServer((req, res) => serve(req, res).catch((error) => {
    res.writeHead(500); res.end(error.message);
  }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseURL = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({headless: true});
});
after(async () => {
  await browser?.close();
  if (server) await new Promise((resolve) => server.close(resolve));
});
beforeEach(async () => {
  state = fixtures();
  context = await browser.newContext({viewport: {width: 1440, height: 1050}, colorScheme: "light"});
  // No test may contact a real cloud service or robot.
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin === baseURL) return route.continue();
    // The exact stylesheet used by web_theme.py, downloaded before running tests.
    if (url.href === "https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css") {
      return route.fulfill({path: path.join(fixtureDir, "materialize.min.css"), contentType: "text/css"});
    }
    if (url.href === "https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js") {
      return route.fulfill({path: path.join(fixtureDir, "materialize.min.js"), contentType: "text/javascript"});
    }
    if (url.hostname === "fonts.googleapis.com" && url.pathname === "/icon") {
      return route.fulfill({body: '@font-face{font-family:"Material Icons";src:url(' + baseURL + '/test-icons.woff2)}.material-icons{font-family:"Material Icons";font-weight:normal;font-style:normal;font-size:24px;line-height:1;letter-spacing:normal;text-transform:none;display:inline-block;white-space:nowrap;word-wrap:normal;direction:ltr;font-feature-settings:"liga"}', contentType: "text/css"});
    }
    return route.abort();
  });
  page = await context.newPage();
  page.setDefaultTimeout(10000);
});
afterEach(async () => { await context?.close(); });

async function ready() {
  await page.goto(`${baseURL}/admin`);
  await page.waitForFunction(() => document.getElementById("overall")?.textContent === "Healthy");
  await page.waitForFunction(() => !document.getElementById("devicePanel").classList.contains("hidden"));
  await page.waitForFunction(() => document.getElementById("scheduleList")?.getAttribute("aria-busy") === "false");
  await page.waitForFunction(() => document.getElementById("activityList").textContent.includes("sample-downstairs"));
  await page.evaluate(() => document.fonts.ready);
  await page.waitForFunction(() => window.M?.version === "1.0.0");
}
async function refresh() {
  await page.locator("#refreshSchedules").click();
  await page.waitForFunction(() => !document.getElementById("refreshSchedules").disabled);
}
async function noOverflow() {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false);
}

function scheduleCard(id = 42, duid = "sample-downstairs") {
  return page.locator(`.schedule-card[data-device-id="${duid}"][data-job-id="${id}"]`);
}

async function visibleScheduleIds() {
  return page.locator(".schedule-card:visible").evaluateAll((cards) => cards.map((card) => Number(card.dataset.jobId)));
}

async function openSchedule(id = 42) {
  const card = scheduleCard(id);
  await card.locator('[data-field="openEditor"]').click();
  return card;
}

test("schedule list includes native jobs and distinguishes server permission from unchecked robot state", async () => {
  await ready();
  await page.waitForFunction(() => document.getElementById("scheduleList").getAttribute("aria-busy") === "false");
  assert.equal(await page.locator("#deviceTitle").textContent(), "Downstairs");
  assert.equal(await page.locator("#scheduleDevice").count(), 0);
  assert.equal(await page.locator(".schedule-card:visible").count(), 3);
  assert.match(await scheduleCard().locator('[data-field="next"]').textContent(), /America\/Los_Angeles/);
  assert.equal(await scheduleCard().getByLabel("Enable schedule", {exact: true}).isChecked(), true);
  assert.equal(await scheduleCard().locator('.schedule-heading input[name="enabled"]').isVisible(), true);
  assert.equal(await scheduleCard(44).getByLabel("Enable schedule", {exact: true}).isEnabled(), true);
  assert.match(await scheduleCard().locator('[data-field="timerState"]').textContent(), /not checked/);
  assert.equal(await scheduleCard(44).locator(".schedule-dialog").isVisible(), false);
  assert.equal(await scheduleCard().locator('[data-field="title"]').textContent(), "09:30");
  assert.equal(await scheduleCard().locator('[data-field="recurrence"]').textContent(), "Weekdays");
  await selectVacuum("Upstairs");
  assert.equal(await page.locator(".schedule-card:visible").count(), 1);
  assert.match(await page.locator("#scheduleSummary").textContent(), /Not connected to this server/);
});

test("schedule edits survive polling and save only changed allowed fields", async () => {
  await ready();
  const card = await openSchedule();
  const originalSettings = structuredClone(state.schedules.devices[0].schedules[0].settings);
  await card.getByLabel("Start time", {exact: true}).fill("10:15");
  await card.getByLabel("Repeat", {exact: true}).selectOption("custom");
  await card.getByLabel("Fri", {exact: true}).uncheck();
  await card.getByLabel("Start time", {exact: true}).focus();
  await page.waitForTimeout(2300);
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "10:15");
  assert.equal(await card.locator(".schedule-dialog").getAttribute("open"), "");
  assert.equal(await page.evaluate(() => document.activeElement.name), "time");
  await card.getByRole("button", {name: "Save schedule"}).click();
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-device-id="sample-downstairs"][data-job-id="42"] [data-field="savedResult"]').textContent.includes("Schedule saved"));
  const request = state.requests.find((item) => item.method === "PATCH");
  assert.deepEqual(request.body, {revision: "revision-42", cron: "15 10 * * 1,2,3,4"});
  assert.deepEqual(state.schedules.devices[0].schedules[0].settings, originalSettings);
  assert.equal(state.schedules.devices[0].schedules[0].native_timer_name, "native-kitchen");
  assert.equal(await card.locator('[data-field="save"]').isDisabled(), true);
});

test("schedule failures preserve edits and revision conflicts require a fresh reload", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Start time", {exact: true}).fill("10:45");
  state.fail.add("/admin/api/schedules/sample-downstairs/42");
  await card.getByRole("button", {name: "Save schedule"}).click();
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-device-id="sample-downstairs"][data-job-id="42"] [data-field="result"]').textContent.includes("failure"));
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "10:45");
  assert.equal(await card.getByRole("button", {name: "Save schedule"}).isEnabled(), true);
  state.fail.clear();
  state.scheduleConflict = true;
  await card.getByRole("button", {name: "Save schedule"}).click();
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-device-id="sample-downstairs"][data-job-id="42"] [data-field="result"]').textContent.includes("Schedule changed"));
  assert.equal(await card.locator('[data-field="save"]').isDisabled(), true);
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "10:45");
  state.schedules.devices[0].schedules[0].cron = "20 12 * * 1-5";
  state.schedules.devices[0].schedules[0].revision = "remote-revision";
  state.scheduleConflict = false;
  await card.getByRole("button", {name: "Discard edits and reload"}).click();
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-device-id="sample-downstairs"][data-job-id="42"] input[name="time"]').value === "12:20");
  assert.equal(await card.locator('[data-field="save"]').isDisabled(), true);
});

test("background schedule changes never overwrite an unsaved form", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Start time", {exact: true}).fill("11:10");
  state.schedules.devices[0].schedules[0].cron = "0 14 * * 1-5";
  state.schedules.devices[0].schedules[0].revision = "changed-by-app";
  await page.evaluate(() => document.getElementById("refreshSchedules").click());
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-device-id="sample-downstairs"][data-job-id="42"] [data-field="editStatus"]').textContent.includes("Changed elsewhere"));
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "11:10");
  assert.equal(await card.locator('[data-field="save"]').isDisabled(), true);
});

test("advanced recurrence survives unrelated permission edits and unsupported API leaves dashboard usable", async () => {
  await ready();
  const card = await openSchedule(43);
  assert.equal(await card.getByLabel("Repeat", {exact: true}).inputValue(), "cron");
  assert.equal(await card.getByLabel("Timezone", {exact: true}).inputValue(), "Europe/Berlin");
  await card.getByRole("button", {name: "Close", exact: true}).click();
  await card.getByLabel("Enable schedule").check();
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-job-id="43"] [data-field="toggleResult"]').textContent.includes("Schedule enabled"));
  assert.deepEqual(state.requests.find((item) => item.method === "PATCH").body, {revision: "revision-43", enabled: true});
  assert.equal(state.schedules.devices[0].schedules[1].cron, "0,30 8-9 * * *");
  state.fail.add("/admin/api/schedules");
  await refresh();
  assert.equal(await page.locator("#scheduleError").isVisible(), true);
  assert.equal(await page.locator("#overall").textContent(), "Healthy");
  assert.match(await page.locator("#activityList").textContent(), /get_status/);
  state.fail.clear();
  await page.locator("#refreshSchedules").click();
  await page.waitForFunction(() => document.getElementById("scheduleError").hidden);
});

test("schedule text is inert and the expanded editor fits a small mobile viewport", async () => {
  state.schedules.devices[0].name = '<img src=x onerror="window.injected=true">';
  state.schedules.devices[0].schedules[0].native_timer_name = '<img src=x onerror="window.injected=true">';
  state.schedules.devices[0].schedules[0].settings.segments = '<script>window.injected=true</script>';
  state.roomCatalog.rooms[0].name = '<img src=x onerror="window.injected=true">';
  await ready();
  const card = await openSchedule();
  await card.locator(".schedule-details > summary").click();
  assert.equal(await page.locator("#schedulePanel img").count(), 0);
  assert.equal(await page.evaluate(() => window.injected), undefined);
  for (const width of [320, 390, 768]) {
    await page.setViewportSize({width, height: 950});
    await noOverflow();
  }
  await page.locator("#schedulePanel").scrollIntoViewIfNeeded();
  await page.screenshot({animations: "disabled", path: path.join(outputDir, "schedule-editor-mobile.png"), fullPage: true});
});

test("header enablement saves immediately while the editor is collapsed and keeps a draft", async () => {
  await ready();
  const card = scheduleCard();
  assert.equal(await card.locator(".schedule-dialog").getAttribute("open"), null);
  await card.getByLabel("Enable schedule", {exact: true}).uncheck();
  await card.getByText("Schedule disabled.", {exact: true}).waitFor();
  assert.deepEqual(state.requests.find((item) => item.method === "PATCH").body, {revision: "revision-42", enabled: false});
  await openSchedule();
  await card.getByLabel("Start time", {exact: true}).fill("11:45");
  await card.getByLabel("Suction", {exact: true}).selectOption("103");
  await card.getByRole("button", {name: "Close", exact: true}).click();
  await card.getByLabel("Enable schedule", {exact: true}).check();
  await card.getByText("Schedule enabled.", {exact: true}).waitFor();
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "11:45");
  assert.equal(await card.getByLabel("Suction", {exact: true}).inputValue(), "103");
  assert.equal(state.schedules.devices[0].schedules[0].settings.fan_power, 102);
  await openSchedule();
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  const request = state.requests.filter((item) => item.method === "PATCH").at(-1);
  assert.equal(request.body.revision, "revision-42-saved-saved");
  assert.equal(request.body.cron, "45 11 * * 1,2,3,4,5");
  assert.deepEqual(request.body.settings, {fan_power: 103});
});

test("failed enablement restores the checkbox and leaves the time draft intact", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Start time", {exact: true}).fill("11:45");
  state.fail.add("/admin/api/schedules/sample-downstairs/42");
  await card.getByRole("button", {name: "Close", exact: true}).click();
  await card.getByLabel("Enable schedule", {exact: true}).uncheck();
  await card.locator('[data-field="toggleResult"]').filter({hasText: "failure"}).waitFor();
  assert.equal(await card.getByLabel("Enable schedule", {exact: true}).isChecked(), true);
  assert.equal(await card.getByLabel("Enable schedule", {exact: true}).isEnabled(), true);
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "11:45");
});

test("native toggles wait for verification and show timer detail only inside the editor", async () => {
  await ready();
  const card = scheduleCard();
  state.timerDelay = 400;
  await card.getByLabel("Enable schedule", {exact: true}).uncheck();
  await card.getByText("Updating and checking schedule…", {exact: true}).waitFor();
  assert.equal(await card.getByLabel("Enable schedule", {exact: true}).isDisabled(), true);
  await card.getByText("Schedule disabled.", {exact: true}).waitFor();
  assert.equal(state.requests.filter((item) => item.method === "PATCH").length, 1);
  assert.match(await card.locator('[data-field="timerState"]').textContent(), /disabled \(verified when saved\)/);
  assert.equal(await card.locator('[data-field="timerState"]').isVisible(), false);
});

for (const failure of ["timerFailure", "unverifiedTimerResponse"]) {
  test(`native toggle does not report success with ${failure}`, async () => {
    await ready();
    state[failure] = true;
    const card = scheduleCard();
    await card.getByLabel("Enable schedule", {exact: true}).uncheck();
    await card.locator('[data-field="toggleResult"].error').waitFor();
    assert.equal(await card.getByLabel("Enable schedule", {exact: true}).isChecked(), true);
    assert.equal(await card.locator('[data-field="toggleResult"].success').count(), 0);
    assert.equal(state.requests.filter((item) => item.method === "PATCH").length, 1);
  });
}

test("named room and cleaning controls send only chosen settings and keep native extras", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Kitchen", {exact: true}).waitFor();
  assert.equal(await card.getByLabel("Kitchen", {exact: true}).isChecked(), true);
  assert.equal(await card.getByLabel("Hall", {exact: true}).isChecked(), true);
  await card.getByLabel("Hall", {exact: true}).uncheck();
  await card.getByLabel("Office", {exact: true}).check();
  await card.getByLabel("Suction", {exact: true}).selectOption({label: "Turbo"});
  await card.getByLabel("Water level", {exact: true}).selectOption({label: "Low"});
  await card.getByLabel("Mopping route", {exact: true}).selectOption({label: "Deep"});
  await card.getByLabel("Cleaning passes", {exact: true}).selectOption({label: "2 passes"});
  await page.evaluate(() => document.getElementById("refreshSchedules").click());
  await page.waitForFunction(() => !document.getElementById("refreshSchedules").disabled);
  assert.equal(await card.getByLabel("Office", {exact: true}).isChecked(), true);
  assert.equal(await card.getByLabel("Water level", {exact: true}).inputValue(), "201");
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  const request = state.requests.find((item) => item.method === "PATCH");
  assert.deepEqual(request.body, {revision: "revision-42", room_revision: "downstairs-rooms-v1",
    settings: {fan_power: 103, water_box_mode: 201, mop_mode: 301, repeat: 2, map_index: 0, segments: "16,18"}});
  assert.equal(state.schedules.devices[0].schedules[0].settings.mop_template_id, 4);
  assert.equal(state.schedules.devices[0].schedules[0].settings.clean_order_mode, 1);
  assert.equal(await card.locator("pre").count(), 0);
});

test("empty room selection is rejected and whole home is explicit", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Kitchen", {exact: true}).uncheck();
  await card.getByLabel("Hall", {exact: true}).uncheck();
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Choose at least one room or select Whole home.", {exact: true}).waitFor();
  assert.equal(state.requests.some((item) => item.method === "PATCH"), false);
  await card.getByLabel("Full", {exact: true}).check();
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  assert.deepEqual(state.requests.find((item) => item.method === "PATCH").body.settings, {map_index: 0, segments: "0"});
});

test("room changes can be reviewed without discarding time and cleaning drafts", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Start time", {exact: true}).fill("11:15");
  await card.getByLabel("Hall", {exact: true}).uncheck();
  state.roomConflict = true;
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.locator('[data-field="result"]').filter({hasText: "room list changed"}).waitFor();
  state.roomCatalog.revision = "downstairs-rooms-v2";
  state.roomCatalog.rooms[0].name = "Dining room";
  await card.getByRole("button", {name: "Refresh rooms", exact: true}).click();
  await card.getByLabel("Dining room", {exact: true}).waitFor();
  assert.equal(await card.getByRole("button", {name: "Save schedule", exact: true}).isDisabled(), true);
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "11:15");
  assert.equal(await card.getByLabel("Dining room", {exact: true}).isChecked(), true);
  await card.getByRole("button", {name: "Use this room selection", exact: true}).click();
  state.roomConflict = false;
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  const request = state.requests.filter((item) => item.method === "PATCH").at(-1);
  assert.equal(request.body.room_revision, "downstairs-rooms-v2");
  assert.equal(request.body.cron, "15 11 * * 1,2,3,4,5");
});

test("map changes clear cross-floor room choices and a failed room read leaves other edits usable", async () => {
  state.schedules.devices[0].schedules[0].settings.map_index = 1;
  await ready();
  const card = await openSchedule();
  await card.getByText("Map and rooms loaded from the vacuum.", {exact: true}).waitFor();
  assert.equal(await card.getByLabel("Rooms", {exact: true}).isDisabled(), true);
  await card.getByLabel("Map", {exact: true}).selectOption("0");
  assert.equal(await card.getByLabel("Kitchen", {exact: true}).isChecked(), false);
  assert.equal(await card.getByLabel("Hall", {exact: true}).isChecked(), false);
  state.fail.add("/admin/api/schedules/sample-downstairs/rooms");
  await card.getByRole("button", {name: "Refresh rooms", exact: true}).click();
  await card.locator('[data-field="roomStatus"]').filter({hasText: "failure"}).waitFor();
  await card.getByRole("button", {name: "Discard edits and reload", exact: true}).click();
  await card.getByText("Loaded the latest saved values.", {exact: true}).waitFor();
  await card.getByLabel("Suction", {exact: true}).selectOption("104");
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  assert.deepEqual(state.requests.find((item) => item.method === "PATCH").body.settings, {fan_power: 104});
});

test("imported custom mode stays selected and is preserved on other edits", async () => {
  state.schedules.devices[0].schedules[0].settings.fan_power = 987;
  await ready();
  const card = await openSchedule();
  assert.equal(await card.getByLabel("Suction", {exact: true}).inputValue(), "987");
  await card.getByLabel("Water level", {exact: true}).selectOption("203");
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  assert.deepEqual(state.requests.find((item) => item.method === "PATCH").body.settings, {water_box_mode: 203});
  assert.equal(state.schedules.devices[0].schedules[0].settings.fan_power, 987);
});

test("repeat presets cover once, every day, weekdays, weekends and custom days", async () => {
  await ready();
  const presets = [
    ["once", "5 8 * * *", false], ["everyday", "5 8 * * *", true],
    ["weekdays", "5 8 * * 1,2,3,4,5", true], ["weekends", "5 8 * * 0,6", true],
  ];
  for (const [preset, cron, repeated] of presets) {
    const card = await openSchedule();
    await card.getByLabel("Start time", {exact: true}).fill("08:05");
    await card.getByLabel("Repeat", {exact: true}).selectOption(preset);
    await card.getByRole("button", {name: "Save schedule", exact: true}).click();
    await card.getByText("Schedule saved.", {exact: true}).waitFor();
    assert.equal(await card.locator("dialog").isVisible(), false);
    assert.equal(state.schedules.devices[0].schedules[0].cron, cron);
    assert.equal(state.schedules.devices[0].schedules[0].repeated, repeated);
  }
  const card = await openSchedule();
  await card.getByLabel("Repeat", {exact: true}).selectOption("custom");
  await card.getByLabel("Sat", {exact: true}).uncheck();
  await card.getByLabel("Sun", {exact: true}).uncheck();
  await card.getByLabel("Mon", {exact: true}).check();
  await card.getByLabel("Thu", {exact: true}).check();
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  assert.equal(state.schedules.devices[0].schedules[0].cron, "5 8 * * 1,4");
});

test("imported dated one-time jobs show their saved start time and Once preset", async () => {
  await ready();
  const card = await openSchedule(44);
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "10:00");
  assert.equal(await card.getByLabel("Repeat", {exact: true}).inputValue(), "once");
  await card.getByLabel("Start time", {exact: true}).fill("11:15");
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  const job = state.schedules.devices[0].schedules[2];
  assert.equal(job.cron, "15 11 * * *");
  assert.equal(job.repeated, false);
  assert.equal(job.native_timer_name, "native-once");
});

test("cleaning mode choices translate to vacuum, mop, combined and per-room preferences", async () => {
  await ready();
  for (const [mode, fan, water, route] of [["vacuum", 102, 200, 300], ["mop", 105, 202, 300], ["custom", 106, 204, 302], ["vac_mop", 102, 202, 300]]) {
    const card = await openSchedule();
    await card.getByLabel("Cleaning mode", {exact: true}).selectOption(mode);
    if (mode === "custom") {
      assert.equal(await card.getByLabel("Suction", {exact: true}).isVisible(), false);
      assert.equal(await card.getByText("Uses the cleaning preferences saved for each room on the vacuum.", {exact: true}).isVisible(), true);
    }
    await card.getByRole("button", {name: "Save schedule", exact: true}).click();
    await card.getByText("Schedule saved.", {exact: true}).waitFor();
    const settings = state.schedules.devices[0].schedules[0].settings;
    assert.deepEqual([settings.fan_power, settings.water_box_mode, settings.mop_mode], [fan, water, route]);
  }
});

test("full cleaning can target another named map without reusing room IDs", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Map", {exact: true}).selectOption({label: "Upstairs"});
  assert.equal(await card.getByLabel("Rooms", {exact: true}).isDisabled(), true);
  await card.getByLabel("Full", {exact: true}).check();
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  assert.deepEqual(state.requests.find((item) => item.method === "PATCH").body.settings, {map_index: 1, segments: "0"});
  assert.equal(await card.locator('[data-field="taskSummary"]').textContent(), "Upstairs · Full");
});

test("another floor loads only on request and its rooms are then selectable", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Map", {exact: true}).selectOption({label: "Upstairs"});
  assert.equal(state.requests.some((item) => item.path.endsWith("/rooms") && item.method === "POST"), false);
  await card.getByRole("button", {name: "Load map and rooms", exact: true}).click();
  await card.getByLabel("Bedroom", {exact: true}).waitFor();
  await card.getByLabel("Bedroom", {exact: true}).check();
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  const request = state.requests.find((item) => item.method === "PATCH");
  assert.equal(request.body.room_revision, "upstairs-rooms-v1");
  assert.deepEqual(request.body.settings, {map_index: 1, segments: "25"});
});

test("compact list and editor fit mobile and expose keyboard focus without script errors", async () => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.setViewportSize({width: 390, height: 844});
  await ready();
  await page.locator("#schedulePanel").scrollIntoViewIfNeeded();
  await page.locator("#scheduleList").screenshot({animations: "disabled", path: path.join(outputDir, "schedule-list-mobile.png")});
  const card = await openSchedule();
  await card.getByLabel("Kitchen", {exact: true}).waitFor();
  for (const width of [320, 390, 768]) {
    await page.setViewportSize({width, height: 844});
    await noOverflow();
    assert.equal(await card.locator("dialog").evaluate((dialog) => dialog.scrollWidth > dialog.clientWidth), false);
  }
  await page.setViewportSize({width: 390, height: 844});
  await card.locator("dialog").screenshot({animations: "disabled", path: path.join(outputDir, "schedule-dialog-mobile.png")});
  await card.getByLabel("Start time", {exact: true}).fill("08:05");
  await page.keyboard.press("Escape");
  assert.equal(await card.locator("dialog").isVisible(), false);
  await openSchedule();
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "08:05");
  assert.deepEqual(errors, []);
});

test("schedule rows sort by earliest clock time, including disabled and multiple-time jobs", async () => {
  const [nineThirty, multiple, ten] = state.schedules.devices[0].schedules;
  const extra = (id, cron) => ({...structuredClone(nineThirty), id, revision: `revision-${id}`, cron});
  state.schedules.devices[0].schedules = [ten, nineThirty, multiple, extra(45, "5 8 * * *"),
    extra(46, "*/15 0-2 * * *"), extra(47, "59 23 * * *"), extra(48, "30 9 * * 0,6"), extra(49, "invalid")];
  const storedOrder = state.schedules.devices[0].schedules.map((job) => job.id);
  await ready();
  await page.waitForFunction(() => document.querySelectorAll('.schedule-card[data-device-id="sample-downstairs"]').length === 8);
  assert.deepEqual(await visibleScheduleIds(), [46, 43, 45, 42, 48, 44, 47, 49]);
  assert.equal(await scheduleCard(43).getByLabel("Enable schedule", {exact: true}).isChecked(), false);
  await refresh();
  assert.deepEqual(await visibleScheduleIds(), [46, 43, 45, 42, 48, 44, 47, 49]);
  assert.deepEqual(state.schedules.devices[0].schedules.map((job) => job.id), storedOrder);
  assert.equal(state.requests.some((request) => request.method === "PATCH"), false);
});

test("sorting preserves an open modal and time draft, then reorders immediately after saving", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Start time", {exact: true}).fill("07:15");
  await card.getByLabel("Start time", {exact: true}).focus();
  state.schedules.devices[0].schedules[1].cron = "0 13 * * *";
  state.schedules.devices[0].schedules[1].revision = "changed-by-app";
  await page.evaluate(() => document.getElementById("refreshSchedules").click());
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-job-id="43"] [data-field="title"]').textContent === "13:00");
  assert.deepEqual(await visibleScheduleIds(), [43, 42, 44]);
  assert.equal(await card.locator("dialog").evaluate((dialog) => dialog.matches(":modal")), true);
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "07:15");
  assert.equal(await page.evaluate(() => document.activeElement.name), "time");
  await card.getByRole("button", {name: "Save schedule", exact: true}).click();
  await card.getByText("Schedule saved.", {exact: true}).waitFor();
  await page.waitForFunction(() => [...document.querySelectorAll('.schedule-card[data-device-id="sample-downstairs"]')].map((card) => card.dataset.jobId).join(",") === "42,44,43");
  assert.deepEqual(await visibleScheduleIds(), [42, 44, 43]);
  assert.equal(await card.locator("dialog").isVisible(), false);
  assert.equal(await page.evaluate(() => document.activeElement?.closest(".schedule-card")?.dataset.jobId), "42");
});

test("list rows show selected room names or Full and keep names separate for each floor and vacuum", async () => {
  const original = state.schedules.devices[0].schedules[0];
  const extra = (id, map, segments) => ({...structuredClone(original), id, revision: `revision-${id}`,
    settings: {...original.settings, map_index: map, segments}});
  state.schedules.devices[0].schedules.push(extra(45, 0, "18"), extra(46, 0, "0"), extra(47, 1, "16"));
  state.schedules.devices[1].schedules[0].settings = {map_index: 0, segments: "16"};
  await ready();
  await scheduleCard().getByText("Downstairs · Kitchen, Hall", {exact: true}).waitFor();
  assert.equal(await scheduleCard(45).locator('[data-field="taskSummary"]').textContent(), "Downstairs · Office");
  assert.equal(await scheduleCard(46).locator('[data-field="taskSummary"]').textContent(), "Downstairs · Full");
  assert.equal(await scheduleCard(47).locator('[data-field="taskSummary"]').textContent(), "Upstairs · Room 16");
  state.roomCatalog = {...state.roomCatalog, map_index: 1, revision: "upstairs-room-names",
    rooms: [{id: 16, room_id: "cloud-bedroom", name: "Bedroom"}]};
  const card = await openSchedule();
  await card.getByRole("button", {name: "Refresh rooms", exact: true}).click();
  await page.waitForFunction(() => document.querySelector('.schedule-card[data-job-id="47"] [data-field="taskSummary"]').textContent === "Upstairs · Bedroom");
  await card.getByRole("button", {name: "Close", exact: true}).click();
  assert.equal(await card.locator('[data-field="taskSummary"]').textContent(), "Downstairs · Kitchen, Hall");
  assert.equal(await scheduleCard(47).locator('[data-field="taskSummary"]').textContent(), "Upstairs · Bedroom");
  await selectVacuum("Upstairs");
  assert.equal(await scheduleCard(42, "sample-upstairs").locator('[data-field="taskSummary"]').textContent(), "Map 1 · Room 16");
});

test("long and untrusted room names wrap completely in compact rows on mobile", async () => {
  const longName = '<img src=x onerror="window.injected=true">' + "VeryLongRoomName".repeat(12);
  state.roomCatalog.rooms[0].name = longName;
  await ready();
  const summary = scheduleCard().locator('[data-field="taskSummary"]');
  await scheduleCard().getByText(`Downstairs · ${longName}, Hall`, {exact: true}).waitFor();
  assert.equal(await page.locator("#scheduleList img").count(), 0);
  assert.equal(await page.evaluate(() => window.injected), undefined);
  for (const width of [320, 390, 768]) {
    await page.setViewportSize({width, height: 950});
    await noOverflow();
    assert.equal(await summary.evaluate((element) => element.scrollWidth > element.clientWidth || element.scrollHeight > element.clientHeight), false);
  }
});

async function selectVacuum(name) {
  await page.locator("#deviceTabs").getByRole("button", {name, exact: true}).click();
  await page.waitForFunction((value) => document.getElementById("deviceTitle").textContent === value, name);
  await page.waitForFunction(() => !document.getElementById("refreshSchedules").disabled);
}

test("shared dashboard keeps activity and server controls while tools follow the selected vacuum", async () => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await ready();
  assert.equal(await page.locator("#credentialList article").count(), 1);
  assert.equal(await page.locator("#serverPanel").isVisible(), false);
  assert.match(await page.locator("#activityList").textContent(), /sample-downstairs/);
  await selectVacuum("Upstairs");
  assert.deepEqual(await visibleScheduleIds(), [42]);
  assert.equal(await page.getByRole("button", {name: "Clear MQTT credentials for Upstairs", exact: true}).isDisabled(), true);
  await page.waitForFunction(() => document.getElementById("activityList").textContent.includes("sample-upstairs"));
  await page.locator("#deviceTabs").getByRole("button", {name: "Server", exact: true}).click();
  await page.locator("#serverPanel").waitFor({state: "visible"});
  assert.equal(await page.locator("#schedulePanel").isVisible(), false);
  assert.equal(await page.locator("#credentialPanel").isVisible(), false);
  assert.equal(await page.locator("#supportLinks a").count(), 3);
  assert.equal(await page.locator("#sendCode").isVisible(), true);
  assert.equal(await page.locator("#saveConnections").isVisible(), true);
  await selectVacuum("Downstairs");
  assert.deepEqual(await visibleScheduleIds(), [43, 42, 44]);
  assert.deepEqual(errors, []);
});

test("switching vacuums or server view preserves each unsaved editor draft", async () => {
  await ready();
  const card = await openSchedule();
  await card.getByLabel("Start time", {exact: true}).fill("07:20");
  // Simulate navigation while the modal is open (a hash link or browser history).
  await page.evaluate(() => { location.hash = "device=sample-upstairs"; });
  await page.waitForFunction(() => document.getElementById("deviceTitle").textContent === "Upstairs");
  assert.equal(await card.locator("dialog").isVisible(), false);
  assert.equal(await scheduleCard(42, "sample-upstairs").locator('[data-field="title"]').textContent(), "11:00");
  await page.locator("#deviceTabs").getByRole("button", {name: "Server", exact: true}).click();
  await page.locator("#serverPanel").waitFor({state: "visible"});
  await selectVacuum("Downstairs");
  await openSchedule();
  assert.equal(await card.getByLabel("Start time", {exact: true}).inputValue(), "07:20");
  assert.equal(await card.getByRole("button", {name: "Save schedule", exact: true}).isEnabled(), true);
  assert.equal(state.requests.some((request) => request.method === "PATCH"), false);
});

test("pending credential reset stays bound to its vacuum across navigation", async () => {
  state.resetDelay = 800;
  state.vacuums[1].mqtt_credentials.saved = true;
  await ready();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true}).click();
  await selectVacuum("Upstairs");
  assert.equal(await page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true}).isVisible(), false);
  await page.waitForTimeout(1000);
  assert.equal(await page.getByRole("button", {name: "Clear MQTT credentials for Upstairs", exact: true}).isEnabled(), true);
  assert.equal(state.vacuums[1].mqtt_credentials.saved, true);
  await selectVacuum("Downstairs");
  assert.equal(await page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true}).isDisabled(), true);
  assert.deepEqual(state.requests.filter((request) => request.method === "DELETE").map((request) => request.path), ["/admin/api/vacuums/sample-downstairs/mqtt-credentials"]);
});

test("shared dashboard fits phone, tablet, desktop and dark mode", async () => {
  await ready();
  await page.screenshot({animations: "disabled", path: path.join(outputDir, "dashboard-desktop.jpg"), type: "jpeg", quality: 60, fullPage: true});
  for (const width of [320, 390, 768]) {
    await page.setViewportSize({width, height: 950});
    await noOverflow();
  }
  await page.setViewportSize({width: 390, height: 844});
  await page.screenshot({animations: "disabled", path: path.join(outputDir, "dashboard-mobile.jpg"), type: "jpeg", quality: 60, fullPage: true});
  const card = await openSchedule();
  await card.getByLabel("Kitchen", {exact: true}).waitFor();
  await card.locator("dialog").screenshot({animations: "disabled", path: path.join(outputDir, "editor-mobile.jpg"), type: "jpeg", quality: 60});
  await page.emulateMedia({colorScheme: "dark"});
  await card.locator("dialog").screenshot({animations: "disabled", path: path.join(outputDir, "editor-dark.jpg"), type: "jpeg", quality: 60});
  await page.keyboard.press("Escape");
  await page.setViewportSize({width: 1280, height: 1000});
  await noOverflow();
  await page.screenshot({animations: "disabled", path: path.join(outputDir, "dashboard-dark.jpg"), type: "jpeg", quality: 60, fullPage: true});
});

test("expired schedule sessions return to the existing sign-in page", async () => {
  await ready();
  state.loggedIn = false;
  await page.locator("#refreshSchedules").click();
  await page.locator("#password").waitFor({state: "visible"});
  assert.equal(await page.locator("#schedulePanel").count(), 0);
  assert.equal(await page.locator('link[href="/admin/static/style.css"]').count(), 1);
});


test("visiting Server during a reset cannot enable a duplicate reset", async () => {
  state.resetDelay = 1500;
  await ready();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true}).click();
  await page.locator("#deviceTabs").getByRole("button", {name: "Server", exact: true}).click();
  await page.locator("#serverPanel").waitFor({state: "visible"});
  await selectVacuum("Downstairs");
  const button = page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true});
  assert.equal(await button.isDisabled(), true);
  assert.equal(await button.textContent(), "Clearing…");
  await page.waitForFunction(() => document.querySelector("#credentialList").textContent.includes("Credentials cleared for Downstairs"));
  assert.equal(await button.isDisabled(), true);
  assert.equal(state.requests.filter((request) => request.method === "DELETE").length, 1);
});

test("a vacuum snapshot taken before reset cannot restore its old credential state", async () => {
  await ready();
  const oldSnapshot = structuredClone(state.vacuums);
  let releaseSnapshot, snapshotStarted;
  const held = new Promise((resolve) => { releaseSnapshot = resolve; });
  const started = new Promise((resolve) => { snapshotStarted = resolve; });
  let intercept = true;
  await page.route("**/admin/api/vacuums", async (route) => {
    if (!intercept) return route.continue();
    intercept = false;
    snapshotStarted();
    await held;
    await route.fulfill({json: {vacuums: oldSnapshot}});
  });
  await page.evaluate(() => window.dispatchEvent(new Event("rls:refresh")));
  await started;
  page.once("dialog", (dialog) => dialog.accept());
  const button = page.getByRole("button", {name: "Clear MQTT credentials for Downstairs", exact: true});
  await button.click();
  await page.waitForFunction(() => document.querySelector("#credentialList").textContent.includes("Credentials cleared for Downstairs"));
  releaseSnapshot();
  await page.waitForTimeout(250);
  assert.equal(await button.isDisabled(), true);
  assert.match(await page.locator("#credentialList").textContent(), /Credentials cleared/);
});
