"use strict";

// Per-vacuum tools embedded in the shared standalone dashboard.
(() => {
  const $ = (id) => document.getElementById(id);
  const credentialCards = new Map();
  const scheduleCards = new Map();
  const scheduleRooms = new Map();
  let scheduleDevices = [];
  let scheduleLoaded = false;
  let schedulePromise = null;
  let scheduleRevision = 0;
  let selectedDuid = "";
  let sessionExpired = false;
  let pollTimer = null;

  function refresh() {
    window.dispatchEvent(new Event("rls:refresh"));
  }

  function text(element, value) {
    const next = String(value ?? "");
    if (element.textContent !== next) element.textContent = next;
  }

  function message(id, value = "", kind = "") {
    const element = $(id);
    text(element, value);
    element.className = `message ${kind}`.trim();
    element.hidden = !value;
  }

  async function fetchJson(url, options = {}, timeout = 15000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, {...options, signal: controller.signal});
      if (response.status === 401) {
        sessionExpired = true;
        clearTimeout(pollTimer);
        window.location.assign("/admin");
        throw new Error("Your session expired. Please sign in again.");
      }
      const payload = await response.json().catch(() => {
        throw new Error("The server returned an unreadable response. Please try again.");
      });
      if (!response.ok) {
        const error = new Error(payload.error || payload.detail || `Request failed (HTTP ${response.status}).`);
        error.status = response.status;
        error.code = payload.code;
        throw error;
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("The server took too long to respond. Please try again.");
      if (error instanceof TypeError) throw new Error("Unable to reach the server. Check your connection and try again.");
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  function emptyState(container, title, description) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const heading = document.createElement("h3");
    heading.textContent = title;
    const copy = document.createElement("p");
    copy.className = "muted";
    copy.textContent = description;
    empty.append(heading, copy);
    container.replaceChildren(empty);
  }

  function renderCredentials(items) {
    const list = $("credentialList");
    list.setAttribute("aria-busy", "false");
    const devices = items.filter((vacuum) => vacuum.duid && vacuum.mqtt_credentials);
    if (!devices.length) {
      // Keep in-flight resets tracked even while the Server view is selected.
      for (const [id, state] of credentialCards) {
        if (state.busy) state.card.hidden = true;
        else { state.card.remove(); credentialCards.delete(id); }
      }
      if (!credentialCards.size) text(list, "No saved vacuum credentials are available.");
      return;
    }
    if (!credentialCards.size) list.replaceChildren();
    const seen = new Set();
    for (const vacuum of devices) {
      const id = String(vacuum.duid);
      seen.add(id);
      let state = credentialCards.get(id);
      if (!state) {
        const card = $("credentialTemplate").content.firstElementChild.cloneNode(true);
        state = {card, vacuum, busy: false};
        credentialCards.set(id, state);
        list.append(card);
        const button = card.querySelector("button");
        button.addEventListener("click", async () => {
          if (state.busy || !state.vacuum.mqtt_credentials.saved) return;
          const name = state.vacuum.name || id;
          if (!window.confirm(`Clear MQTT credentials for ${name}? This disconnects this vacuum. You will need to re-pair it using Add vacuum in LocalRock. Its inventory entry, keys, schedules, and app logins are kept.`)) return;
          const result = card.querySelector('[data-field="result"]');
          state.busy = true;
          window.dispatchEvent(new Event("rls:vacuum-mutation"));
          updateCredentialCard(state);
          result.hidden = true;
          try {
            const payload = await fetchJson(`/admin/api/vacuums/${encodeURIComponent(id)}/mqtt-credentials`, {method: "DELETE"});
            state.vacuum = {...state.vacuum, mqtt_credentials: payload.mqtt_credentials, connected: false};
            text(result, `Credentials cleared for ${name}. Enable Allow new connections, reset this vacuum’s Wi-Fi, then use Add vacuum in LocalRock to re-pair it.`);
            result.className = "message success";
          } catch (error) {
            text(result, error.message);
            result.className = "message error";
          } finally {
            window.dispatchEvent(new Event("rls:vacuum-mutation"));
            state.busy = false;
            result.hidden = false;
            updateCredentialCard(state);
          }
          await refresh();
        });
      }
      if (!state.busy) state.vacuum = vacuum;
      updateCredentialCard(state);
    }
    for (const [id, state] of credentialCards) {
      if (!seen.has(id) && !state.busy) { state.card.remove(); credentialCards.delete(id); }
    }
  }

  function updateCredentialCard(state) {
    const {card, vacuum, busy} = state;
    const credentials = vacuum.mqtt_credentials;
    const name = vacuum.name || vacuum.duid;
    text(card.querySelector('[data-field="name"]'), name);
    text(card.querySelector('[data-field="detail"]'), credentials.saved ? "MQTT credentials saved" : credentials.cleared_at ? "Credentials cleared · Re-pair this vacuum to connect" : "No MQTT credentials saved");
    const button = card.querySelector("button");
    button.disabled = busy || !credentials.saved;
    button.setAttribute("aria-label", `Clear MQTT credentials for ${name}`);
    text(button, busy ? "Clearing…" : "Clear MQTT credentials");
  }

  const scheduleDayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  function simpleRecurrence(cron) {
    const parts = String(cron || "").trim().split(/\s+/);
    if (parts.length !== 5 || !/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])
        || !["*", "?"].includes(parts[2]) || !["*", "?"].includes(parts[3])) return null;
    const minute = Number(parts[0]), hour = Number(parts[1]);
    if (minute > 59 || hour > 23) return null;
    const days = new Set();
    if (["*", "?"].includes(parts[4])) [0, 1, 2, 3, 4, 5, 6].forEach((day) => days.add(day));
    else {
      for (const part of parts[4].split(",")) {
        const match = /^([0-7])(?:-([0-7]))?$/.exec(part);
        if (!match) return null;
        const start = Number(match[1]), end = Number(match[2] ?? match[1]);
        if (end < start) return null;
        for (let day = start; day <= end; day += 1) days.add(day % 7);
      }
    }
    return {time: `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`, days: [...days].sort()};
  }

  function scheduleField(state, name) { return state.card.querySelector(`[data-field="${name}"]`); }

  function scheduleMessage(state, value = "", kind = "") {
    const element = scheduleField(state, "result");
    text(element, value);
    element.className = `message ${kind}`.trim();
    element.hidden = !value;
  }

  const cleaningKeys = ["fan_power", "water_box_mode", "mop_mode", "repeat"];
  const repeatDays = {everyday: [0, 1, 2, 3, 4, 5, 6], weekdays: [1, 2, 3, 4, 5], weekends: [0, 6], once: [0, 1, 2, 3, 4, 5, 6]};

  function singleScheduleTime(cron) {
    const [minute, hour] = String(cron || "").trim().split(/\s+/);
    if (!/^\d+$/.test(minute) || !/^\d+$/.test(hour) || Number(minute) > 59 || Number(hour) > 23) return null;
    return `${String(Number(hour)).padStart(2, "0")}:${String(Number(minute)).padStart(2, "0")}`;
  }

  function firstCronValue(field, maximum) {
    let first = Infinity;
    for (const part of String(field ?? "").split(",")) {
      const match = /^(\*|\?|\d+(?:-\d+)?)?(?:\/(\d+))?$/.exec(part);
      if (!match || (!match[1] && !match[2]) || (match[2] !== undefined && Number(match[2]) < 1)) return Infinity;
      const range = match[1] || "*";
      const [start, end] = ["*", "?"].includes(range) ? [0, maximum] : range.split("-").map(Number);
      if (start > maximum || (end !== undefined && (end < start || end > maximum))) return Infinity;
      first = Math.min(first, start);
    }
    return first;
  }

  function scheduleStartMinute(cron) {
    const parts = String(cron || "").trim().split(/\s+/);
    if (parts.length !== 5) return Infinity;
    // Multiple-time expressions sort by their earliest clock time, including
    // disabled schedules with no next_run_at value.
    return firstCronValue(parts[1], 23) * 60 + firstCronValue(parts[0], 59);
  }

  function sortScheduleCards() {
    const states = [...scheduleCards.values()];
    // Moving an open dialog's ancestor can remove it from the browser's modal
    // layer. Apply any pending order when the editor closes instead.
    if (states.some((state) => state.dialog.open)) return;
    states.sort((a, b) => a.startMinute === b.startMinute ? 0 : a.startMinute - b.startMinute);
    const list = $("scheduleList"), focused = document.activeElement;
    const keepFocus = list.contains(focused);
    let cursor = list.firstElementChild;
    for (const state of states) {
      if (state.card === cursor) cursor = cursor.nextElementSibling;
      else list.insertBefore(state.card, cursor);
    }
    if (keepFocus && document.activeElement !== focused) focused.focus({preventScroll: true});
  }

  function repeatPreset(job, simple) {
    if (job.repeated === false && singleScheduleTime(job.cron)) return "once";
    if (!simple) return "cron";
    for (const key of ["everyday", "weekdays", "weekends"]) if (JSON.stringify(simple.days) === JSON.stringify(repeatDays[key])) return key;
    return "custom";
  }

  function cleaningMode(settings) {
    const fan = Number(settings.fan_power), water = Number(settings.water_box_mode), mop = Number(settings.mop_mode);
    if (fan === 106 || water === 204 || mop === 302) return "custom";
    if (fan === 105 && water > 200) return "mop";
    if ([101, 102, 103, 104, 108, 109].includes(fan)) {
      if (water === 200) return "vacuum";
      if ([201, 202, 203, 225, 235, 245].includes(water)) return "vac_mop";
    }
    return "keep";
  }

  const cleaningModeNames = {vacuum: "Vacuum", vac_mop: "Vac & mop", mop: "Mop", custom: "Custom", keep: "Saved mode"};

  function chooseCleaningMode(state, mode) {
    const fields = state.form.elements;
    const set = (key, value) => { fields[key].value = String(value); };
    if (mode === "custom") {
      set("fan_power", 106); set("water_box_mode", 204); set("mop_mode", 302);
    } else if (mode !== "keep") {
      const fan = Number(fields.fan_power.value), water = Number(fields.water_box_mode.value);
      if (mode === "mop") set("fan_power", 105);
      else if (![101, 102, 103, 104, 108, 109].includes(fan)) set("fan_power", 102);
      if (mode === "vacuum") set("water_box_mode", 200);
      else if (![201, 202, 203, 225, 235, 245].includes(water)) set("water_box_mode", 202);
      if (!fields.mop_mode.value || [302, 306].includes(Number(fields.mop_mode.value))) set("mop_mode", 300);
    }
  }

  function savedRoomSelection(settings) {
    const raw = settings.segments ?? "0";
    const parts = Array.isArray(raw) ? raw : String(raw).split(/[,;]/).map((item) => item.trim());
    const valid = parts.length && parts.every((item) => /^\d+$/.test(String(item)) && Number(item) <= 255);
    const ids = valid ? parts.map(Number) : [];
    return {map: settings.map_index === -1 ? "" : String(settings.map_index ?? ""), area: valid && ids.length === 1 && ids[0] === 0 ? "whole"
      : valid && ids.every((id) => id > 0) ? "rooms" : "keep", ids: ids.filter((id) => id > 0)};
  }

  function roomEdits(state) {
    return state.savedValues && JSON.stringify(state.roomDraft) !== JSON.stringify(JSON.parse(state.savedValues).rooms);
  }

  function addOption(select, value, label, disabled = false) {
    const option = document.createElement("option");
    option.value = String(value);
    option.textContent = label;
    option.disabled = disabled;
    select.append(option);
  }

  function populateCleaning(state, job) {
    for (const key of cleaningKeys) {
      const select = state.form.elements[key];
      select.replaceChildren();
      addOption(select, "", Object.hasOwn(job.settings || {}, key) ? "Keep saved setting" : "Use vacuum setting");
      for (const option of job.setting_choices?.[key] || []) addOption(select, option.value, option.label);
      const current = job.settings?.[key];
      if (Number.isInteger(current) && ![...select.options].some((option) => option.value === String(current))) {
        addOption(select, current, `Saved custom option (${current})`);
      }
      select.value = Number.isInteger(current) ? String(current) : "";
      // The blank option means retain an imported/missing value, not erase it.
      select.options[0].disabled = Number.isInteger(current);
    }
    const list = scheduleField(state, "extraList");
    list.replaceChildren();
    for (const [key, label] of [["clean_order_mode", "Cleaning order"], ["clean_mop", "Mop preparation"], ["mop_template_id", "Mop template"]]) {
      if (!Object.hasOwn(job.settings || {}, key)) continue;
      const row = document.createElement("div"), term = document.createElement("dt"), value = document.createElement("dd");
      term.textContent = label;
      const saved = job.settings[key];
      value.textContent = typeof saved === "number" || typeof saved === "string" ? `Saved ${key === "mop_template_id" ? "template" : "option"} ${saved}` : "Saved custom setting";
      row.append(term, value);
      list.append(row);
    }
    scheduleField(state, "extraOptions").hidden = !list.children.length;
    text(scheduleField(state, "cleaningHelp"), job.settings_editable
      ? "Choose your cleaning preferences, then Save schedule. Options supported by your model may vary. Saved custom settings are kept."
      : "Cleaning settings for this schedule format are shown for reference. Edit them in LocalRock.");
  }

  function renderRoomControls(state) {
    const cached = scheduleRooms.get(state.deviceId), catalog = cached?.catalog;
    const draft = state.roomDraft, form = state.form;
    form.elements.map.replaceChildren();
    const maps = catalog?.maps || [];
    if (!maps.some((map) => String(map.id) === draft.map)) {
      addOption(form.elements.map, draft.map, draft.map === "" ? "Use loaded map" : `Saved map ${Number(draft.map) + 1}`);
    }
    for (const map of maps) {
      const loaded = map.id === catalog.map_index;
      addOption(form.elements.map, map.id, map.name + (loaded ? " (loaded)" : ""));
    }
    form.elements.map.value = draft.map;
    form.elements.area.value = draft.area;
    scheduleField(state, "keepArea").hidden = draft.area !== "keep";
    const matches = catalog && (draft.map === "" || Number(draft.map) === catalog.map_index);
    const list = scheduleField(state, "roomList");
    list.replaceChildren();
    const rooms = matches ? [...catalog.rooms] : [];
    for (const id of draft.ids) {
      if (!rooms.some((room) => room.id === id)) rooms.push({id, name: `Room ${id} (saved; unavailable on loaded map)`, unavailable: true});
    }
    for (const room of rooms) {
      const label = document.createElement("label"), input = document.createElement("input"), name = document.createElement("span");
      label.className = "room-choice";
      input.type = "checkbox";
      input.name = "room";
      input.value = String(room.id);
      input.checked = draft.ids.includes(room.id);
      // A removed room can be unchecked, but cannot be newly selected.
      input.disabled = room.unavailable && !input.checked;
      name.textContent = room.name;
      label.append(input, name);
      list.append(label);
    }
    if (!rooms.length) text(list, catalog && matches ? "No named rooms reported on this map." : "Refresh rooms to load the room names.");
    text(scheduleField(state, "mapHelp"), matches || draft.area === "whole" ? ""
      : "Load this map to choose its rooms. The vacuum must be idle or docked. Full cleans the entire selected map.");
    text(scheduleField(state, "roomStatus"), cached?.busy ? "Reading map and room names from the vacuum…"
      : cached?.error || (catalog ? "Map and rooms loaded from the vacuum." : "Connect this vacuum to load its map and room names."));
    state.form.querySelector(".schedule-rooms").hidden = draft.area !== "rooms";
  }

  async function refreshRooms(duid, loadMap) {
    const cached = scheduleRooms.get(duid) || {};
    if (cached.busy) return;
    cached.busy = true;
    cached.attempted = true;
    cached.error = "";
    scheduleRooms.set(duid, cached);
    const update = () => {
      for (const state of scheduleCards.values()) if (state.deviceId === duid) {
        renderRoomControls(state);
        renderScheduleSummary(state, state.latest || state.base);
        syncScheduleEditor(state);
      }
    };
    update();
    try {
      const options = loadMap === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({map_index: loadMap})};
      const catalog = await fetchJson(`/admin/api/schedules/${encodeURIComponent(duid)}/rooms`, options, 40000);
      if (!Array.isArray(catalog.rooms) || !Array.isArray(catalog.maps) || !catalog.revision || !Number.isInteger(catalog.map_index)) {
        throw new Error("The room response was incomplete. Try Refresh rooms again.");
      }
      cached.catalog = catalog;
      // Names from a floor remain useful in list rows after another floor is
      // loaded. The editor and save validation still use only the live catalog.
      cached.catalogs ??= new Map();
      cached.catalogs.set(catalog.map_index, catalog);
      for (const mapId of cached.catalogs.keys()) {
        if (!catalog.maps.some((map) => map.id === mapId)) cached.catalogs.delete(mapId);
      }
      for (const state of scheduleCards.values()) if (state.deviceId === duid) {
        if (loadMap !== undefined && Number(state.roomDraft.map) === loadMap && !state.roomDraft.ids.length) {
          state.roomRevision = catalog.revision;
          state.roomNeedsReview = false;
        } else if (roomEdits(state) && state.roomRevision !== catalog.revision) state.roomNeedsReview = true;
        else if (!roomEdits(state)) { state.roomRevision = catalog.revision; state.roomNeedsReview = false; }
      }
    } catch (error) {
      cached.error = error.message;
    } finally {
      cached.busy = false;
      update();
    }
  }

  function scheduleValues(state) {
    const form = state.form;
    return {
      mode: form.elements.mode.value,
      time: form.elements.time.value,
      days: [...form.querySelectorAll('input[name="day"]:checked')].map((input) => Number(input.value)).sort(),
      cron: form.elements.cron.value.trim(),
      zone: form.elements.zone.value.trim(),
      cleaning: Object.fromEntries(cleaningKeys.map((key) => [key, form.elements[key].value])),
      rooms: state.roomDraft,
    };
  }

  function syncScheduleEditor(state) {
    const values = scheduleValues(state);
    const relevant = (value) => value.mode !== "cron"
      ? {mode: value.mode, time: value.time, days: value.mode === "custom" ? value.days : [], zone: value.zone, cleaning: value.cleaning, rooms: value.rooms}
      : {mode: value.mode, cron: value.cron, zone: value.zone, cleaning: value.cleaning, rooms: value.rooms};
    state.dirty = JSON.stringify(relevant(values)) !== JSON.stringify(relevant(JSON.parse(state.savedValues)));
    const stale = state.forcedConflict || (state.dirty && state.latest?.revision !== state.base?.revision);
    const editable = state.base?.editable === true && !state.deleted;
    state.form.querySelector(".schedule-fields").disabled = state.busy || !editable;
    scheduleField(state, "closeEditor").disabled = state.busy;
    state.card.querySelector('input[name="enabled"]').disabled = state.busy || !editable || stale;
    const cached = scheduleRooms.get(state.deviceId), catalog = cached?.catalog;
    state.form.querySelector(".cleaning-fields").disabled = !state.base?.settings_editable;
    state.form.elements.map.disabled = !catalog || cached.busy;
    const matches = catalog && (state.roomDraft.map === "" || Number(state.roomDraft.map) === catalog.map_index);
    state.form.querySelector(".schedule-area").disabled = !catalog || cached?.busy === true;
    state.form.querySelector('input[name="area"][value="rooms"]').disabled = !matches;
    state.form.querySelector(".schedule-rooms").disabled = !matches || cached.busy;
    scheduleField(state, "refreshRooms").disabled = state.busy || cached?.busy === true;
    scheduleField(state, "loadMap").hidden = !catalog || matches;
    scheduleField(state, "loadMap").disabled = state.busy || cached?.busy === true;
    scheduleField(state, "roomReview").hidden = !state.roomNeedsReview;
    scheduleField(state, "confirmRooms").hidden = !state.roomNeedsReview;
    scheduleField(state, "confirmRooms").disabled = (!matches && state.roomDraft.area !== "whole") || cached?.busy === true;
    scheduleField(state, "timeField").hidden = values.mode === "cron";
    scheduleField(state, "daysField").hidden = values.mode !== "custom";
    scheduleField(state, "onceHelp").hidden = values.mode !== "once";
    scheduleField(state, "cronField").hidden = values.mode !== "cron";
    state.form.elements.time.required = values.mode !== "cron";
    state.form.elements.cron.required = values.mode === "cron";
    const cleanMode = cleaningMode(values.cleaning);
    state.form.elements.cleaning_mode.value = cleanMode;
    scheduleField(state, "customHelp").hidden = cleanMode !== "custom";
    scheduleField(state, "suctionField").hidden = ["custom", "mop"].includes(cleanMode);
    scheduleField(state, "waterField").hidden = ["custom", "vacuum"].includes(cleanMode);
    scheduleField(state, "mopField").hidden = ["custom", "vacuum"].includes(cleanMode);
    text(scheduleField(state, "selectionCount"), state.roomDraft.area === "whole" ? "Entire map" : `${state.roomDraft.ids.length} room${state.roomDraft.ids.length === 1 ? "" : "s"} selected`);
    const save = scheduleField(state, "save");
    save.disabled = !editable || !state.dirty || state.busy || stale || (roomEdits(state) && (state.roomNeedsReview || cached?.busy === true));
    text(save, state.busy ? "Saving…" : "Save schedule");
    scheduleField(state, "discard").disabled = state.busy || !(state.dirty || stale || state.deleted);
    text(scheduleField(state, "editStatus"), state.busy ? "Saving…" : state.deleted ? "Deleted elsewhere"
      : stale ? "Changed elsewhere — discard edits to load the latest values"
      : state.dirty ? "Unsaved changes" : "Saved");
  }

  function adoptSchedule(state, job) {
    state.base = job;
    state.latest = job;
    state.deleted = false;
    state.forcedConflict = false;
    const simple = simpleRecurrence(job.cron);
    const form = state.form;
    form.elements.mode.value = repeatPreset(job, simple);
    form.elements.time.value = singleScheduleTime(job.cron) || "09:00";
    form.elements.zone.value = job.timeZoneId || "";
    form.elements.cron.value = job.cron || "";
    state.card.querySelector('input[name="enabled"]').checked = job.enabled === true;
    state.roomDraft = savedRoomSelection(job.settings || {});
    state.roomRevision = scheduleRooms.get(state.deviceId)?.catalog?.revision;
    state.roomNeedsReview = false;
    populateCleaning(state, job);
    renderRoomControls(state);
    form.querySelectorAll('input[name="day"]').forEach((input) => {
      input.checked = (simple?.days || [1, 2, 3, 4, 5]).includes(Number(input.value));
    });
    state.savedValues = JSON.stringify(scheduleValues(state));
    syncScheduleEditor(state);
  }

  function schedulePatch(state) {
    const values = scheduleValues(state), original = JSON.parse(state.savedValues);
    const patch = {revision: state.base.revision};
    if (values.zone !== original.zone) patch.timeZoneId = values.zone;
    const settings = {};
    for (const key of cleaningKeys) if (values.cleaning[key] !== original.cleaning[key] && values.cleaning[key] !== "") settings[key] = Number(values.cleaning[key]);
    if (roomEdits(state)) {
      const catalog = scheduleRooms.get(state.deviceId)?.catalog;
      if (!catalog || state.roomNeedsReview) throw new Error("Refresh rooms and review your selection before saving.");
      if (values.rooms.area === "keep") throw new Error("Choose whole home or selected rooms.");
      if (values.rooms.area === "rooms" && !values.rooms.ids.length) throw new Error("Choose at least one room or select Whole home.");
      if (values.rooms.area === "rooms" && values.rooms.ids.some((id) => !catalog.rooms.some((room) => room.id === id))) throw new Error("Remove unavailable rooms before saving.");
      settings.map_index = values.rooms.map === "" ? catalog.map_index : Number(values.rooms.map);
      settings.segments = values.rooms.area === "whole" ? "0" : values.rooms.ids.join(",");
      patch.room_revision = state.roomRevision;
    }
    if (Object.keys(settings).length) patch.settings = settings;
    if (values.mode !== "cron" && (values.mode !== "once") !== state.base.repeated) patch.repeated = values.mode !== "once";
    if (values.mode !== original.mode || (values.mode === "cron" && values.cron !== original.cron)
        || (values.mode !== "cron" && (values.time !== original.time || (values.mode === "custom" && JSON.stringify(values.days) !== JSON.stringify(original.days))))) {
      if (values.mode === "cron") patch.cron = values.cron;
      else {
        const days = repeatDays[values.mode] || values.days;
        if (!days.length) throw new Error("Choose at least one day for this recurring schedule.");
        if (!/^\d{2}:\d{2}$/.test(values.time)) throw new Error("Choose a valid time.");
        const [hour, minute] = values.time.split(":").map(Number);
        patch.cron = `${minute} ${hour} * * ${days.length === 7 ? "*" : days.join(",")}`;
      }
    }
    return patch;
  }

  function renderScheduleSummary(state, job) {
    state.startMinute = scheduleStartMinute(job.cron);
    const simple = simpleRecurrence(job.cron);
    const preset = repeatPreset(job, simple);
    const days = {once: "Once", everyday: "Every day", weekdays: "Weekdays", weekends: "Weekends"}[preset] || [1, 2, 3, 4, 5, 6, 0]
      .filter((day) => simple?.days.includes(day)).map((day) => scheduleDayNames[day]).join(", ");
    const clock = singleScheduleTime(job.cron) || "Multiple times";
    text(scheduleField(state, "title"), clock);
    text(scheduleField(state, "recurrence"), job.repeated === false ? "Once" : days || "Advanced");
    scheduleField(state, "openEditor").setAttribute("aria-label", `Edit schedule ${job.id}, ${clock}`);
    const cached = scheduleRooms.get(state.deviceId), catalog = cached?.catalog;
    const selection = savedRoomSelection(job.settings || {});
    const map = catalog?.maps.find((item) => String(item.id) === selection.map);
    const mapName = map?.name || (selection.map === "" ? "Loaded map" : `Map ${Number(selection.map) + 1}`);
    const mapId = selection.map === "" ? catalog?.map_index : Number(selection.map);
    const roomCatalog = cached?.catalogs?.get(mapId);
    const selectedRooms = selection.ids.map((id) => roomCatalog?.rooms.find((room) => room.id === id)?.name || `Room ${id}`).join(", ");
    text(scheduleField(state, "taskSummary"), `${mapName} · ${selection.area === "whole" ? "Full" : selection.area === "rooms" ? selectedRooms : "Saved rooms"}`);
    text(scheduleField(state, "modeSummary"), cleaningModeNames[cleaningMode(job.settings || {})]);
    if (!state.busy) state.card.querySelector('input[name="enabled"]').checked = job.enabled === true;
    let next = job.enabled ? "Next scheduled time: not calculated" : "Disabled on this server";
    if (job.enabled && job.next_run_at) {
      try {
        next = "Next scheduled time: " + new Intl.DateTimeFormat(undefined, {
          dateStyle: "medium", timeStyle: "short", timeZone: job.timeZoneId,
        }).format(new Date(job.next_run_at)) + ` (${job.timeZoneId})`;
      } catch { next = `Next scheduled time: ${job.next_run_at}`; }
    }
    text(scheduleField(state, "next"), next);
    const timerDetail = job.native_timer_state === "on" ? "enabled (verified when saved)"
      : job.native_timer_state === "off" ? "disabled (verified when saved)" : "not checked in this view";
    text(scheduleField(state, "timerState"), job.native_timer_name
      ? `Robot timer: ${timerDetail}.`
      : "This schedule uses the server's legacy timer compatibility mode.");
    text(scheduleField(state, "enabledHelp"), job.native_timer_name
      ? "Changes are saved after the vacuum confirms its timer setting."
      : "Enable schedule saves immediately. Unchecked: this server will not run it.");
  }

  function createScheduleCard(device, job, key) {
    const card = $("scheduleTemplate").content.firstElementChild.cloneNode(true);
    card.dataset.jobId = String(job.id);
    card.dataset.deviceId = String(device.duid);
    const state = {card, form: card.querySelector("form"), deviceId: String(device.duid), busy: false, dirty: false};
    state.dialog = card.querySelector("dialog");
    state.form.setAttribute("aria-label", `Edit schedule ${job.id} for ${device.name || "vacuum"}`);
    adoptSchedule(state, job);
    scheduleField(state, "openEditor").addEventListener("click", () => {
      state.dialog.showModal();
      state.dialog.scrollTop = 0;
    });
    scheduleField(state, "closeEditor").addEventListener("click", () => state.dialog.close());
    state.dialog.addEventListener("close", sortScheduleCards);
    state.dialog.addEventListener("cancel", (event) => { if (state.busy) event.preventDefault(); });
    const onInput = (event) => {
      const input = event.target, draft = state.roomDraft;
      if (input.name === "cleaning_mode") {
        chooseCleaningMode(state, input.value);
      } else if (input.name === "mode" && repeatDays[input.value]) {
        state.form.querySelectorAll('input[name="day"]').forEach((day) => { day.checked = repeatDays[input.value].includes(Number(day.value)); });
      } else if (input.name === "map" && input.value !== draft.map) {
        draft.map = input.value;
        draft.ids = [];
        if (draft.area === "keep") draft.area = "rooms";
        renderRoomControls(state);
      } else if (input.name === "area") {
        draft.area = input.value;
        renderRoomControls(state);
      } else if (input.name === "room") {
        const id = Number(input.value);
        draft.ids = input.checked ? [...new Set([...draft.ids, id])] : draft.ids.filter((item) => item !== id);
      }
      if (["map", "area", "room"].includes(input.name) && !state.roomNeedsReview) {
        state.roomRevision = scheduleRooms.get(state.deviceId)?.catalog?.revision;
      }
      scheduleMessage(state);
      scheduleField(state, "savedResult").hidden = true;
      syncScheduleEditor(state);
    };
    state.form.addEventListener("input", onInput);
    state.form.addEventListener("change", onInput);
    scheduleField(state, "refreshRooms").addEventListener("click", () => refreshRooms(state.deviceId));
    scheduleField(state, "loadMap").addEventListener("click", () => refreshRooms(state.deviceId, Number(state.roomDraft.map)));
    scheduleField(state, "confirmRooms").addEventListener("click", () => {
      state.roomRevision = scheduleRooms.get(state.deviceId)?.catalog?.revision;
      state.roomNeedsReview = false;
      scheduleMessage(state, "Room selection reviewed. Save schedule to apply it.");
      syncScheduleEditor(state);
    });
    const toggle = card.querySelector('input[name="enabled"]');
    toggle.addEventListener("change", async () => {
      if (state.busy) return;
      state.busy = true;
      scheduleRevision += 1;
      syncScheduleEditor(state);
      const result = scheduleField(state, "toggleResult");
      result.hidden = false;
      result.className = "message";
      text(result, state.base.native_timer_name ? "Updating and checking schedule…" : "Saving schedule…");
      try {
        const payload = await fetchJson(`/admin/api/schedules/${encodeURIComponent(state.deviceId)}/${encodeURIComponent(state.base.id)}`, {
          method: "PATCH", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({revision: state.base.revision, enabled: toggle.checked}),
        }, 55000);
        if (!payload.schedule?.revision) throw new Error("The save response was incomplete. Refresh schedules to check the saved state.");
        if (payload.schedule.enabled !== toggle.checked || (state.base.native_timer_name
            && payload.schedule.native_timer_state !== (toggle.checked ? "on" : "off"))) {
          throw new Error("The timer change was not verified. Refresh schedules before retrying.");
        }
        // Only enablement changed: retain unsaved time and cleaning controls.
        state.base = payload.schedule;
        state.latest = payload.schedule;
        renderScheduleSummary(state, payload.schedule);
        text(result, payload.schedule.enabled ? "Schedule enabled." : "Schedule disabled.");
        result.className = "message success";
      } catch (error) {
        if (error.status === 409) state.forcedConflict = true;
        text(result, error.message);
        result.className = "message error";
      } finally {
        toggle.checked = state.base.enabled === true;
        state.busy = false;
        scheduleRevision += 1;
        syncScheduleEditor(state);
      }
    });
    scheduleField(state, "discard").addEventListener("click", async () => {
      if (state.busy) return;
      state.busy = true;
      scheduleRevision += 1;
      syncScheduleEditor(state);
      try {
        const payload = await fetchJson("/admin/api/schedules");
        if (payload.supported === false) throw new Error("Schedule editing is not available in this server build.");
        if (!Array.isArray(payload.devices)) throw new Error("The schedule response was incomplete. Try refreshing.");
        const device = payload.devices.find((item) => String(item.duid) === state.deviceId);
        const latest = device?.schedules?.find((item) => String(item.id) === String(state.base.id));
        if (latest) {
          adoptSchedule(state, latest);
          renderScheduleSummary(state, latest);
          scheduleMessage(state, "Loaded the latest saved values.", "success");
        } else {
          card.remove();
          scheduleCards.delete(key);
        }
        state.busy = false;
        renderSchedules(payload);
      } catch (error) {
        scheduleMessage(state, `Could not reload. Your edits are still here. ${error.message}`, "error");
      } finally {
        state.busy = false;
        scheduleRevision += 1;
        syncScheduleEditor(state);
      }
    });
    state.form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (scheduleField(state, "save").disabled) return;
      let patch;
      try { patch = schedulePatch(state); }
      catch (error) { scheduleMessage(state, error.message, "error"); return; }
      state.busy = true;
      scheduleRevision += 1;
      syncScheduleEditor(state);
      scheduleMessage(state);
      try {
        const payload = await fetchJson(`/admin/api/schedules/${encodeURIComponent(state.deviceId)}/${encodeURIComponent(state.base.id)}`, {
          method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify(patch),
        }, 40000);
        if (!payload.schedule?.revision) throw new Error("The save response was incomplete. Refresh schedules before trying again.");
        adoptSchedule(state, payload.schedule);
        renderScheduleSummary(state, payload.schedule);
        scheduleMessage(state);
        const savedResult = scheduleField(state, "savedResult");
        text(savedResult, "Schedule saved.");
        savedResult.hidden = false;
        savedResult.className = "message success";
        state.dialog.close();
      } catch (error) {
        if (error.code === "room_catalog_changed") state.roomNeedsReview = true;
        else if (error.status === 409) state.forcedConflict = true;
        scheduleMessage(state, error.message, "error");
      } finally {
        state.busy = false;
        scheduleRevision += 1;
        syncScheduleEditor(state);
      }
    });
    return state;
  }

  function selectScheduleDevice() {
    const duid = selectedDuid;
    const device = scheduleDevices.find((item) => String(item.duid) === duid);
    let shown = 0;
    for (const state of scheduleCards.values()) {
      state.card.hidden = state.deviceId !== duid;
      if (state.card.hidden && state.dialog.open) state.dialog.close();
      if (!state.card.hidden) shown += 1;
    }
    $("scheduleList").querySelector(".schedule-empty")?.remove();
    if (!shown) {
      const empty = document.createElement("div");
      empty.className = "schedule-empty empty-state";
      const heading = document.createElement("h3");
      heading.textContent = "No stored schedules for this vacuum";
      const copy = document.createElement("p");
      copy.className = "muted";
      copy.textContent = "This editor shows jobs saved on the local server, including imported schedules.";
      empty.append(heading, copy);
      $("scheduleList").append(empty);
    }
    const count = device?.schedules?.length || 0;
    text($("scheduleSummary"), device ? `${count} stored schedule${count === 1 ? "" : "s"} · `
      + (device.connected === true ? "Connected locally" : device.connected === false ? "Not connected to this server; edits affect local data only" : "Connection not reported") : "No saved schedules for this vacuum");
    if (device?.connected && device.schedules?.some((job) => job.settings_editable) && !scheduleRooms.get(duid)?.attempted) refreshRooms(duid);
  }

  function renderSchedules(payload) {
    if (payload.supported === false) throw new Error("Schedule editing is not available in this server build.");
    if (!Array.isArray(payload.devices)) throw new Error("The schedule response was incomplete. Try refreshing.");
    scheduleDevices = payload.devices;
    if (!scheduleLoaded) { $("scheduleList").replaceChildren(); scheduleLoaded = true; }
    const seen = new Set();
    for (const device of scheduleDevices) {
      for (const job of Array.isArray(device.schedules) ? device.schedules : []) {
        const key = JSON.stringify([String(device.duid), String(job.id)]);
        seen.add(key);
        let state = scheduleCards.get(key);
        if (!state) {
          state = createScheduleCard(device, job, key);
          scheduleCards.set(key, state);
          $("scheduleList").append(state.card);
        } else if (!state.busy) {
          state.latest = job;
          if (!state.dirty && !state.forcedConflict && state.base.revision !== job.revision) adoptSchedule(state, job);
        }
        renderScheduleSummary(state, state.busy ? state.base : job);
        syncScheduleEditor(state);
      }
    }
    for (const [key, state] of scheduleCards) {
      if (seen.has(key) || state.busy) continue;
      if (state.dirty || state.forcedConflict) {
        state.deleted = true;
        scheduleMessage(state, "This schedule was deleted elsewhere. Your edits have not been saved.", "error");
        renderScheduleSummary(state, state.base);
        syncScheduleEditor(state);
      } else { state.card.remove(); scheduleCards.delete(key); }
    }
    selectScheduleDevice();
    sortScheduleCards();
  }

  async function refreshScheduleData() {
    if (schedulePromise) return schedulePromise;
    const revision = scheduleRevision;
    $("refreshSchedules").disabled = true;
    schedulePromise = (async () => {
      try {
        const payload = await fetchJson("/admin/api/schedules");
        if (revision !== scheduleRevision || sessionExpired) return;
        renderSchedules(payload);
        message("scheduleError");
      } catch (error) {
        if (!sessionExpired) {
          message("scheduleError", `Schedules could not be refreshed. ${error.message} Use Refresh schedules to retry.`, "error");
          if (!scheduleLoaded) emptyState($("scheduleList"), "Schedules unavailable", "The rest of the dashboard is available. Refresh schedules to try again.");
        }
      } finally {
        $("scheduleList").setAttribute("aria-busy", "false");
        $("refreshSchedules").disabled = false;
        schedulePromise = null;
      }
    })();
    return schedulePromise;
  }


  function schedulePoll() {
    clearTimeout(pollTimer);
    if (!selectedDuid || document.hidden || sessionExpired) return;
    pollTimer = setTimeout(async () => {
      await refreshScheduleData();
      schedulePoll();
    }, 15000);
  }

  window.addEventListener("rls:vacuum-selected", (event) => {
    const vacuum = event.detail;
    const nextDuid = String(vacuum?.duid || "");
    const changed = selectedDuid !== nextDuid;
    selectedDuid = nextDuid;
    renderCredentials(vacuum ? [vacuum] : []);
    for (const state of credentialCards.values()) {
      state.card.hidden = String(state.vacuum.duid) !== selectedDuid;
    }
    if (changed) {
      selectScheduleDevice();
      if (selectedDuid && !document.hidden) refreshScheduleData();
      schedulePoll();
    }
  });
  $("refreshSchedules").addEventListener("click", refreshScheduleData);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && selectedDuid) refreshScheduleData();
    schedulePoll();
  });
})();
