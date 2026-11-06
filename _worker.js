// lib/security.ts
var ApiError = class extends Error {
  status;
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
};
var categories = ["primary", "middle", "high", "friends"];
async function digest(value) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))), (b) => b.toString(16).padStart(2, "0")).join("");
}
function safeEqual(a, b) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
function randomToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
}
function text(value, max, required = false) {
  if (typeof value !== "string") value = "";
  const s = value.trim();
  if (required && !s || s.length > max) throw new ApiError(required && !s ? "\u8BF7\u586B\u5199\u5FC5\u586B\u5185\u5BB9\u3002" : `\u5185\u5BB9\u6700\u591A ${max} \u5B57\u3002`);
  return s;
}
function accessCodes(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 10) throw new ApiError("\u8BF7\u586B\u5199 1 \u5230 10 \u4E2A\u8BBF\u95EE\u53E3\u4EE4\u3002");
  const codes = value.map((code) => {
    if (typeof code !== "string") throw new ApiError("\u8BBF\u95EE\u53E3\u4EE4\u683C\u5F0F\u4E0D\u6B63\u786E\u3002");
    const clean = code.trim();
    if (clean.length < 2 || clean.length > 128) throw new ApiError("\u6BCF\u4E2A\u8BBF\u95EE\u53E3\u4EE4\u9700\u8981 2 \u5230 128 \u4E2A\u5B57\u7B26\u3002");
    return clean;
  });
  return [...new Set(codes)];
}
function configuredAccessCodes(env) {
  return accessCodes(env.ALBUM_CODES?.trim() ? env.ALBUM_CODES.split(/[,，\r\n]+/).map((code) => code.trim()).filter(Boolean) : [env.ALBUM_CODE, env.ALBUM_CODE_ALT].filter((code) => !!code));
}
function validateMemory(input) {
  const title = text(input.title, 80, true), nickname = text(input.nickname, 30, true), body = text(input.body, 5e3);
  const category = text(input.category, 20);
  if (!categories.includes(category)) throw new ApiError("\u8BF7\u9009\u62E9\u6B63\u786E\u7684\u56DE\u5FC6\u5206\u7C7B\u3002");
  const happenedAt = text(input.happenedAt, 10);
  if (happenedAt && (!/^\d{4}-\d{2}-\d{2}$/.test(happenedAt) || Number.isNaN(Date.parse(happenedAt)) || new Date(happenedAt).toISOString().slice(0, 10) !== happenedAt)) throw new ApiError("\u8BF7\u9009\u62E9\u6709\u6548\u7684\u65E5\u671F\u3002");
  const tags = [...new Set(text(input.tags, 400).split(/[,，、\n]/).map((x) => x.trim()).filter(Boolean))];
  if (tags.length > 10 || tags.some((x) => x.length > 30)) throw new ApiError("\u6700\u591A\u586B\u5199 10 \u4F4D\u670B\u53CB\uFF0C\u6BCF\u4E2A\u540D\u5B57\u6700\u591A 30 \u5B57\u3002");
  return { title, nickname, body, category, happenedAt, tags };
}
function parseRange(header, size) {
  const match = /^bytes=(\d*)-(\d*)$/.exec(header);
  if (!match || !match[1] && !match[2]) throw new ApiError("\u65E0\u6548\u7684\u97F3\u9891\u8303\u56F4\u3002", 416);
  let start = match[1] ? Number(match[1]) : Math.max(0, size - Number(match[2]));
  let end = match[1] ? match[2] ? Math.min(Number(match[2]), size - 1) : size - 1 : size - 1;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start >= size || end < start) throw new ApiError("\u65E0\u6548\u7684\u97F3\u9891\u8303\u56F4\u3002", 416);
  return { offset: start, length: end - start + 1 };
}
function cookieValue(request, name) {
  return request.headers.get("cookie")?.split(";").map((x) => x.trim()).find((x) => x.startsWith(name + "="))?.slice(name.length + 1) || "";
}
function cookie(request, name, value, days) {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(days * 86400)}${new URL(request.url).protocol === "https:" ? "; Secure" : ""}`;
}
async function boundedForm(request) {
  const limit = 32 * 1024 * 1024;
  if (Number(request.headers.get("content-length") || 0) > limit) throw new ApiError("\u6BCF\u6B21\u53D1\u5E03\u9644\u4EF6\u5408\u8BA1\u4E0D\u80FD\u8D85\u8FC7 30 MB\u3002", 413);
  const reader = request.body?.getReader();
  if (!reader) throw new ApiError("\u6CA1\u6709\u63D0\u4EA4\u5185\u5BB9\u3002");
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new ApiError("\u6BCF\u6B21\u53D1\u5E03\u9644\u4EF6\u5408\u8BA1\u4E0D\u80FD\u8D85\u8FC7 30 MB\u3002", 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return new Request(request.url, { method: "POST", headers: { "content-type": request.headers.get("content-type") || "" }, body: bytes }).formData();
}

// lib/copy.ts
var sections = {
  "\u5DF2\u6253\u5305\u56FE\u5E93": [
    ["pack.photoLimit", "\u56FE\u5E93\u7167\u7247\u9650\u5236", "\u6700\u591A\u9009\u62E9 9 \u5F20"],
    ["pack.hint", "\u56FE\u5E93\u4F7F\u7528\u63D0\u793A", "\u4ECE\u7F51\u7AD9\u5DF2\u6536\u5F55\u7684\u7167\u7247\u4E2D\u9009\u62E9\u3002\u6DFB\u52A0\u65B0\u7167\u7247\u6216\u97F3\u4E50\uFF0C\u9700\u8981\u7528\u6253\u5305\u52A9\u624B\u91CD\u65B0\u4E0A\u4F20\u7F51\u7AD9\u3002"],
    ["pack.loading", "\u56FE\u5E93\u52A0\u8F7D\u63D0\u793A", "\u6B63\u5728\u6253\u5F00\u56FE\u5E93\u2026"],
    ["pack.empty", "\u7A7A\u56FE\u5E93\u8BF4\u660E", "\u56FE\u5E93\u91CC\u8FD8\u6CA1\u6709\u7167\u7247\uFF0C\u4E5F\u53EF\u4EE5\u5148\u5199\u4E0B\u6587\u5B57\u56DE\u5FC6\u3002"],
    ["pack.noAudio", "\u4E0D\u914D\u97F3\u4E50\u9009\u9879", "\u4E0D\u6DFB\u52A0\u97F3\u4E50"]
  ],
  "\u5165\u53E3\u9875": [
    ["brand.english", "\u540D\u5B57\u4E0B\u65B9\u82F1\u6587", "OUR LITTLE TIME CAPSULE"],
    ["gate.private", "\u79C1\u5BC6\u63D0\u793A", "\u53EA\u5C5E\u4E8E\u6211\u4EEC\u7684\u65F6\u5149"],
    ["gate.eyebrow", "\u9996\u9875\u82F1\u6587\u5C0F\u6807\u9898", "A PLACE TO REMEMBER"],
    ["gate.title", "\u9996\u9875\u5927\u6807\u9898", "\u6709\u4E9B\u65F6\u5149\uFF0C\n\u503C\u5F97\u53CD\u590D\u7FFB\u9605\u3002"],
    ["gate.intro", "\u9996\u9875\u4ECB\u7ECD", "\u4ECE\u7B2C\u4E00\u58F0\u4E0B\u8BFE\u94C3\uFF0C\u5230\u6BCF\u4E00\u6B21\u4E45\u522B\u91CD\u9022\u3002\n\u628A\u7167\u7247\u3001\u6545\u4E8B\u548C\u559C\u6B22\u7684\u6B4C\uFF0C\n\u7559\u5728\u8FD9\u672C\u5C5E\u4E8E\u6211\u4EEC\u7684\u7EAA\u5FF5\u518C\u3002"],
    ["gate.label", "\u53E3\u4EE4\u63D0\u95EE", "\u8FD8\u8BB0\u5F97\uFF0C\u6211\u4EEC\u4E4B\u95F4\u7684\u6697\u53F7\u5417\uFF1F"],
    ["gate.placeholder", "\u53E3\u4EE4\u8F93\u5165\u63D0\u793A", "\u8F93\u5165\u4E13\u5C5E\u53E3\u4EE4"],
    ["gate.enter", "\u8FDB\u5165\u6309\u94AE", "\u8FDB\u5165\u6211\u4EEC\u7684\u7EAA\u5FF5\u518C"],
    ["gate.connecting", "\u8FDE\u63A5\u63D0\u793A", "\u6B63\u5728\u8FDE\u63A5\u7EAA\u5FF5\u518C\u2026"],
    ["gate.opening", "\u6253\u5F00\u63D0\u793A", "\u6B63\u5728\u6253\u5F00\u65F6\u5149\u2026"],
    ["gate.music", "\u97F3\u4E50\u63D0\u793A", "\u8FDB\u5165\u540E\u5C06\u5C1D\u8BD5\u64AD\u653E\u4F60\u6DFB\u52A0\u7684\u97F3\u4E50\uFF0C\u53EF\u4EE5\u968F\u65F6\u6682\u505C\u3002"],
    ["gate.note", "\u9996\u9875\u5BC4\u8BED", "\u732E\u7ED9\u6BCF\u4E00\u4E2A\uFF0C\u820D\u4E0D\u5F97\u5FD8\u8BB0\u7684\u77AC\u95F4\u3002"],
    ["gate.footer", "\u9996\u9875\u9875\u811A", "\u65F6\u5149\u4F1A\u8D70\u8FDC\uFF0C\u6545\u4E8B\u4F1A\u7559\u4E0B\u3002"],
    ["gate.footerEnglish", "\u9996\u9875\u9875\u811A\u82F1\u6587", "MADE FOR THE DAYS WE SHARE"]
  ],
  "\u56DE\u5FC6\u6D4F\u89C8": [
    ["reader.sample", "\u793A\u4F8B\u6807\u8BB0", "\u793A\u4F8B\u56DE\u5FC6"],
    ["reader.up", "\u4E0A\u6ED1\u63D0\u793A", "\u5411\u4E0A\u6ED1\uFF0C\u7EE7\u7EED\u7FFB\u9605"],
    ["reader.last", "\u6700\u540E\u4E00\u6BB5\u63D0\u793A", "\u628A\u60F3\u8BF4\u7684\u8BDD\uFF0C\u7559\u5728\u6700\u540E\u4E00\u9875"],
    ["reader.audio", "\u97F3\u4E50\u6807\u8BB0", "\u9644\u6709\u97F3\u4E50"],
    ["reader.photos", "\u7167\u7247\u6570\u91CF", "{count} \u5F20\u7167\u7247"],
    ["reader.with", "\u670B\u53CB\u7F72\u540D", "\u4E0E {names}"],
    ["reader.audioOnly", "\u97F3\u4E50\u56DE\u5FC6\u7B80\u4ECB", "\u6709\u4E00\u9996\u6B4C\uFF0C\u60F3\u548C\u4F60\u4E00\u8D77\u542C\u3002"],
    ["reader.loading", "\u52A0\u8F7D\u6587\u5B57", "\u6B63\u5728\u7FFB\u5F00\u6211\u4EEC\u7684\u6545\u4E8B\u2026"],
    ["reader.error", "\u52A0\u8F7D\u5931\u8D25\u6807\u9898", "\u6545\u4E8B\u6682\u65F6\u6CA1\u6709\u6253\u5F00"],
    ["reader.retry", "\u91CD\u8BD5\u6309\u94AE", "\u91CD\u65B0\u52A0\u8F7D"],
    ["reader.emptyTitle", "\u7A7A\u767D\u9875\u6807\u9898", "\u8FD9\u4E00\u9875\uFF0C\u7B49\u4F60\u6765\u5199"],
    ["reader.emptyBody", "\u7A7A\u767D\u9875\u4ECB\u7ECD", "\u4E00\u5F20\u7167\u7247\u3001\u4E00\u6BB5\u6587\u5B57\u3001\u4E00\u9996\u6B4C\uFF0C\n\u90FD\u662F\u6545\u4E8B\u7684\u5F00\u59CB\u3002"],
    ["reader.emptyEnglish", "\u7A7A\u767D\u9875\u82F1\u6587", "A NEW PAGE BEGINS"],
    ["reader.first", "\u7B2C\u4E00\u6BB5\u6309\u94AE", "\u5199\u4E0B\u7B2C\u4E00\u6BB5\u56DE\u5FC6"],
    ["reader.previous", "\u4E0A\u4E00\u6BB5\u6309\u94AE", "\u4E0A\u4E00\u6BB5\u56DE\u5FC6"],
    ["reader.next", "\u4E0B\u4E00\u6BB5\u6309\u94AE", "\u4E0B\u4E00\u6BB5\u56DE\u5FC6"],
    ["reader.position", "\u7FFB\u9875\u64AD\u62A5", "\u7B2C {index} \u6BB5\uFF0C\u5171 {count} \u6BB5\u56DE\u5FC6"],
    ["category.primary", "\u5C0F\u5B66\u540D\u79F0", "\u5C0F\u5B66\u65F6\u5149"],
    ["category.middle", "\u521D\u4E2D\u540D\u79F0", "\u521D\u4E2D\u65F6\u5149"],
    ["category.high", "\u9AD8\u4E2D\u540D\u79F0", "\u9AD8\u4E2D\u65F6\u5149"],
    ["category.friends", "\u670B\u53CB\u540D\u79F0", "\u5173\u4E8E\u670B\u53CB"],
    ["dock.write", "\u5199\u56DE\u5FC6\u6309\u94AE", "\u5199\u4E0B\u56DE\u5FC6"],
    ["dock.manage", "\u540E\u53F0\u6309\u94AE", "\u7BA1\u7406\u7EAA\u5FF5\u518C"],
    ["dock.addMusic", "\u6DFB\u52A0\u97F3\u4E50\u6309\u94AE", "\u6DFB\u52A0\u97F3\u4E50"],
    ["dock.musicName", "\u80CC\u666F\u97F3\u4E50\u540D\u79F0", "\u6211\u4EEC\u7684\u80CC\u666F\u97F3\u4E50"],
    ["dock.playing", "\u64AD\u653E\u63D0\u793A", "\u65CB\u5F8B\u6B63\u5728\u8F7B\u8F7B\u6D41\u6DCC"],
    ["dock.blocked", "\u624B\u52A8\u64AD\u653E\u63D0\u793A", "\u70B9\u64AD\u653E\uFF0C\u5F00\u542F\u97F3\u4E50"],
    ["dock.paused", "\u6682\u505C\u63D0\u793A", "\u5C5E\u4E8E\u6211\u4EEC\u7684\u65CB\u5F8B"],
    ["dock.play", "\u64AD\u653E\u6309\u94AE", "\u64AD\u653E\u80CC\u666F\u97F3\u4E50"],
    ["dock.pause", "\u6682\u505C\u6309\u94AE", "\u6682\u505C\u80CC\u666F\u97F3\u4E50"],
    ["dock.invite", "\u9080\u8BF7\u6309\u94AE", "\u9080\u8BF7\u670B\u53CB"],
    ["dock.exit", "\u79BB\u5F00\u6309\u94AE", "\u5408\u4E0A\u7EAA\u5FF5\u518C"],
    ["notice.saved", "\u56DE\u5FC6\u4FDD\u5B58\u63D0\u793A", "\u8FD9\u6BB5\u65F6\u5149\uFF0C\u5DF2\u7ECF\u66FF\u4F60\u6536\u85CF\u597D\u4E86\u3002"],
    ["notice.deleted", "\u56DE\u5FC6\u5220\u9664\u63D0\u793A", "\u8FD9\u6BB5\u56DE\u5FC6\u5DF2\u5220\u9664\u3002"],
    ["notice.settings", "\u8BBE\u7F6E\u4FDD\u5B58\u63D0\u793A", "\u7EAA\u5FF5\u518C\u8BBE\u7F6E\u5DF2\u4FDD\u5B58\u3002"],
    ["notice.invite", "\u590D\u5236\u94FE\u63A5\u63D0\u793A", "\u94FE\u63A5\u5DF2\u590D\u5236\uFF0C\u8BB0\u5F97\u628A\u8BBF\u95EE\u53E3\u4EE4\u79C1\u4E0B\u544A\u8BC9\u670B\u53CB\u3002"],
    ["notice.copyFailed", "\u590D\u5236\u5931\u8D25\u63D0\u793A", "\u8BF7\u590D\u5236\u6D4F\u89C8\u5668\u5730\u5740\u680F\u4E2D\u7684\u94FE\u63A5\uFF0C\u53D1\u7ED9\u670B\u53CB\u3002"]
  ],
  "\u7559\u8A00\u7ED3\u5C3E": [
    ["guest.eyebrow", "\u7559\u8A00\u82F1\u6587\u5C0F\u6807\u9898", "SOME WORDS STAY FOREVER"],
    ["guest.title", "\u7559\u8A00\u6807\u9898", "\u628A\u60F3\u8BF4\u7684\u8BDD\uFF0C\u7559\u5728\u8FD9\u91CC"],
    ["guest.intro", "\u7559\u8A00\u4ECB\u7ECD", "\u7FFB\u5230\u6700\u540E\uFF0C\u6545\u4E8B\u8FD8\u6CA1\u6709\u7ED3\u675F\u3002\n\u7559\u4E00\u53E5\u95EE\u5019\uFF0C\u8BA9\u670B\u53CB\u77E5\u9053\u4F60\u6765\u8FC7\u3002"],
    ["guest.empty", "\u8FD8\u6CA1\u6709\u7559\u8A00", "\u8FD8\u6CA1\u6709\u7559\u8A00\uFF0C\u6765\u5199\u4E0B\u7B2C\u4E00\u53E5\u95EE\u5019\u5427\u3002"],
    ["guest.nickname", "\u7559\u8A00\u6635\u79F0\u6807\u7B7E", "\u4F60\u7684\u6635\u79F0"],
    ["guest.nicknamePlaceholder", "\u7559\u8A00\u6635\u79F0\u63D0\u793A", "\u8BA9\u670B\u53CB\u77E5\u9053\u662F\u4F60"],
    ["guest.body", "\u7559\u8A00\u5185\u5BB9\u6807\u7B7E", "\u60F3\u5BF9\u5927\u5BB6\u8BF4\u7684\u8BDD"],
    ["guest.placeholder", "\u7559\u8A00\u8F93\u5165\u63D0\u793A", "\u597D\u4E45\u4E0D\u89C1\uFF0C\u6700\u8FD1\u8FD8\u597D\u5417\uFF1F"],
    ["guest.submit", "\u7559\u8A00\u6309\u94AE", "\u7559\u4E0B\u7559\u8A00"],
    ["guest.sending", "\u7559\u8A00\u63D0\u4EA4\u63D0\u793A", "\u6B63\u5728\u9001\u51FA\u2026"],
    ["guest.sent", "\u7559\u8A00\u6210\u529F\u63D0\u793A", "\u4F60\u7684\u7559\u8A00\uFF0C\u5DF2\u7ECF\u7559\u5728\u6700\u540E\u4E00\u9875\u3002"],
    ["guest.back", "\u8FD4\u56DE\u56DE\u5FC6\u6309\u94AE", "\u56DE\u5230\u56DE\u5FC6"],
    ["guest.edit", "\u7F16\u8F91\u7559\u8A00\u6309\u94AE", "\u7F16\u8F91\u7559\u8A00"],
    ["guest.delete", "\u5220\u9664\u7559\u8A00\u6309\u94AE", "\u5220\u9664\u7559\u8A00"],
    ["guest.confirmDelete", "\u5220\u9664\u7559\u8A00\u786E\u8BA4", "\u786E\u5B9A\u5220\u9664\u8FD9\u6761\u7559\u8A00\u5417\uFF1F"],
    ["guest.ownerNote", "\u7559\u8A00\u6743\u9650\u8BF4\u660E", "\u7559\u8A00\u7531\u7EAA\u5FF5\u518C\u4E3B\u4EBA\u7BA1\u7406\u3002"]
  ],
  "\u56DE\u5FC6\u8BE6\u60C5\u4E0E\u586B\u5199": [
    ["detail.title", "\u8BE6\u60C5\u5F39\u7A97\u6807\u9898", "\u7FFB\u5F00\u8FD9\u4E00\u9875"],
    ["detail.sample", "\u8BE6\u60C5\u793A\u4F8B\u6807\u8BB0", "\u793A\u4F8B\u56DE\u5FC6 \xB7 \u975E\u771F\u5B9E\u8BB0\u5F55"],
    ["detail.audio", "\u56DE\u5FC6\u97F3\u4E50\u6807\u9898", "\u5C5E\u4E8E\u8FD9\u6BB5\u56DE\u5FC6\u7684\u65CB\u5F8B"],
    ["detail.edit", "\u7F16\u8F91\u56DE\u5FC6\u6309\u94AE", "\u7F16\u8F91\u56DE\u5FC6"],
    ["detail.delete", "\u5220\u9664\u56DE\u5FC6\u6309\u94AE", "\u5220\u9664\u56DE\u5FC6"],
    ["detail.deleting", "\u5220\u9664\u4E2D\u63D0\u793A", "\u6B63\u5728\u5220\u9664\u2026"],
    ["detail.confirmDelete", "\u56DE\u5FC6\u5220\u9664\u786E\u8BA4", "\u786E\u5B9A\u5220\u9664\u8FD9\u6BB5\u56DE\u5FC6\u5417\uFF1F\u7167\u7247\u3001\u6587\u5B57\u548C\u9644\u5E26\u97F3\u4E50\u4E5F\u4F1A\u4E00\u8D77\u5220\u9664\u3002"],
    ["detail.sampleNote", "\u793A\u4F8B\u8BF4\u660E", "\u8FD9\u662F\u4E00\u9875\u793A\u4F8B\u6587\u5B57\uFF0C\u7528\u6765\u5C55\u793A\u7EAA\u5FF5\u518C\u7684\u6837\u5B50\u3002\u70B9\u300C\u5199\u4E0B\u56DE\u5FC6\u300D\uFF0C\u5F00\u59CB\u6536\u85CF\u4F60\u4EEC\u81EA\u5DF1\u7684\u7167\u7247\u548C\u6545\u4E8B\u3002"],
    ["editor.new", "\u65B0\u5EFA\u6807\u9898", "\u5199\u4E0B\u4E00\u6BB5\u56DE\u5FC6"],
    ["editor.edit", "\u4FEE\u6539\u6807\u9898", "\u518D\u6DFB\u51E0\u7B14\u56DE\u5FC6"],
    ["editor.intro", "\u586B\u5199\u4ECB\u7ECD", "\u7167\u7247\u8BB0\u4F4F\u753B\u9762\uFF0C\u6587\u5B57\u7559\u4F4F\u5F53\u65F6\u7684\u5FC3\u60C5\u3002"],
    ["editor.title", "\u56DE\u5FC6\u6807\u9898\u6807\u7B7E", "\u7ED9\u8FD9\u6BB5\u56DE\u5FC6\u8D77\u4E2A\u540D\u5B57"],
    ["editor.titlePlaceholder", "\u6807\u9898\u63D0\u793A", "\u6BD4\u5982\uFF1A\u90A3\u4E2A\u4E0D\u60F3\u8BF4\u518D\u89C1\u7684\u590F\u5929"],
    ["editor.nickname", "\u4F5C\u8005\u6807\u7B7E", "\u4F60\u7684\u6635\u79F0"],
    ["editor.nicknamePlaceholder", "\u4F5C\u8005\u63D0\u793A", "\u8BA9\u670B\u53CB\u77E5\u9053\u662F\u4F60"],
    ["editor.category", "\u5206\u7C7B\u6807\u7B7E", "\u5C5E\u4E8E\u54EA\u6BB5\u65F6\u5149"],
    ["editor.body", "\u6B63\u6587\u6807\u7B7E", "\u8BB0\u5F97\u90A3\u65F6\u7684\u6545\u4E8B\u5417"],
    ["editor.bodyPlaceholder", "\u6B63\u6587\u63D0\u793A", "\u90A3\u5929\u53D1\u751F\u4E86\u4EC0\u4E48\uFF1F\u8C01\u5728\u8EAB\u8FB9\uFF1F\u6709\u4EC0\u4E48\u4E00\u76F4\u6CA1\u8BF4\u51FA\u53E3\u7684\u8BDD\u2026\u2026"],
    ["editor.friends", "\u670B\u53CB\u6807\u7B7E", "\u4E00\u8D77\u51FA\u73B0\u7684\u670B\u53CB"],
    ["editor.friendsPlaceholder", "\u670B\u53CB\u63D0\u793A", "\u591A\u4E2A\u540D\u5B57\u7528\u9017\u53F7\u9694\u5F00"],
    ["editor.photos", "\u7167\u7247\u6807\u7B7E", "\u653E\u8FDB\u51E0\u5F20\u7167\u7247"],
    ["editor.photoLimit", "\u7167\u7247\u9650\u5236\u63D0\u793A", "\u6700\u591A 9 \u5F20 \xB7 \u6BCF\u5F20 10 MB"],
    ["editor.addPhoto", "\u6DFB\u52A0\u7167\u7247\u6309\u94AE", "\u6DFB\u52A0\u7167\u7247"],
    ["editor.audio", "\u56DE\u5FC6\u914D\u4E50\u6807\u7B7E", "\u7ED9\u56DE\u5FC6\u914D\u4E00\u9996\u6B4C"],
    ["editor.audioKept", "\u5DF2\u6DFB\u52A0\u97F3\u4E50\u63D0\u793A", "\u5DF2\u6DFB\u52A0\u4E00\u9996\u97F3\u4E50"],
    ["editor.audioHint", "\u97F3\u4E50\u9650\u5236\u63D0\u793A", "\u53EF\u9009 \xB7 MP3 / M4A \xB7 \u6700\u5927 20 MB"],
    ["editor.chooseAudio", "\u9009\u62E9\u97F3\u4E50\u6309\u94AE", "\u9009\u62E9\u97F3\u4E50"],
    ["editor.footer", "\u4FDD\u5B58\u8BF4\u660E", "\u4FDD\u5B58\u540E\uFF0C\u670B\u53CB\u4EEC\u5C31\u80FD\u770B\u89C1\u8FD9\u6BB5\u56DE\u5FC6\u3002"],
    ["editor.saving", "\u4FDD\u5B58\u4E2D\u63D0\u793A", "\u6B63\u5728\u6536\u85CF\u2026"],
    ["editor.save", "\u4FDD\u5B58\u4FEE\u6539\u6309\u94AE", "\u4FDD\u5B58\u4FEE\u6539"],
    ["editor.create", "\u65B0\u56DE\u5FC6\u4FDD\u5B58\u6309\u94AE", "\u6536\u85CF\u8FD9\u6BB5\u65F6\u5149"],
    ["editor.confirmClose", "\u672A\u4FDD\u5B58\u786E\u8BA4", "\u8FD9\u6BB5\u56DE\u5FC6\u8FD8\u6CA1\u6709\u4FDD\u5B58\uFF0C\u786E\u5B9A\u5148\u79BB\u5F00\u5417\uFF1F"],
    ["common.close", "\u5173\u95ED\u6309\u94AE", "\u5173\u95ED"],
    ["common.save", "\u4FDD\u5B58\u6309\u94AE", "\u4FDD\u5B58"],
    ["common.cancel", "\u53D6\u6D88\u6309\u94AE", "\u53D6\u6D88"],
    ["common.remove", "\u79FB\u9664\u6309\u94AE", "\u79FB\u9664"],
    ["common.edit", "\u7F16\u8F91\u6309\u94AE", "\u7F16\u8F91"],
    ["common.deleting", "\u5220\u9664\u4E2D", "\u6B63\u5728\u5220\u9664\u2026"],
    ["common.saving", "\u4FDD\u5B58\u4E2D", "\u6B63\u5728\u4FDD\u5B58\u2026"],
    ["common.photo", "\u7167\u7247\u653E\u5927\u6807\u9898", "\u7167\u7247\u653E\u5927\u67E5\u770B"]
  ],
  "\u793A\u4F8B\u56DE\u5FC6": [
    ["demo.1.title", "\u793A\u4F8B\u4E00\u6807\u9898", "\u90A3\u5E74\u590F\u5929\uFF0C\u6211\u4EEC\u6BD5\u4E1A\u4E86"],
    ["demo.1.body", "\u793A\u4F8B\u4E00\u6B63\u6587", "\u64CD\u573A\u4E0A\u7684\u98CE\uFF0C\u8D70\u5ECA\u91CC\u7684\u7B11\u58F0\uFF0C\u8FD8\u6709\u90A3\u5F20\u603B\u6709\u4EBA\u95ED\u773C\u7684\u6BD5\u4E1A\u7167\u3002\n\n\u628A\u4F60\u7684\u5408\u7167\u548C\u6545\u4E8B\u653E\u5728\u8FD9\u91CC\uFF0C\u8BA9\u90A3\u4E9B\u5E74\u91CD\u65B0\u6709\u4E86\u6E29\u5EA6\u3002"],
    ["demo.2.title", "\u793A\u4F8B\u4E8C\u6807\u9898", "\u653E\u5B66\u540E\uFF0C\u518D\u591A\u8D70\u4E00\u6BB5\u8DEF"],
    ["demo.2.body", "\u793A\u4F8B\u4E8C\u6B63\u6587", "\u5C0F\u65F6\u5019\u603B\u89C9\u5F97\uFF0C\u653E\u5B66\u7684\u8DEF\u5F88\u957F\u3002\u957F\u5927\u4EE5\u540E\u624D\u53D1\u73B0\uFF0C\u6700\u60F3\u518D\u8D70\u4E00\u6B21\u7684\uFF0C\u4E5F\u662F\u90A3\u6BB5\u8DEF\u3002\n\n\u8FD9\u662F\u793A\u4F8B\u56DE\u5FC6\uFF0C\u7B49\u4F60\u7528\u81EA\u5DF1\u7684\u6545\u4E8B\u6765\u66FF\u6362\u3002"],
    ["demo.3.title", "\u793A\u4F8B\u4E09\u6807\u9898", "\u6709\u4F60\u4EEC\u5728\uFF0C\u5E73\u51E1\u4E5F\u95EA\u95EA\u53D1\u5149"],
    ["demo.3.body", "\u793A\u4F8B\u4E09\u6B63\u6587", "\u672A\u5FC5\u6BCF\u6B21\u89C1\u9762\u90FD\u6709\u7279\u522B\u7684\u4E8B\uFF0C\u4F46\u548C\u4F60\u4EEC\u5728\u4E00\u8D77\uFF0C\u5C31\u8DB3\u591F\u503C\u5F97\u88AB\u8BB0\u5F55\u3002\n\n\u5199\u4E0B\u4E00\u4E2A\u540D\u5B57\u3001\u4E00\u53E5\u8BB0\u5F97\u7684\u8BDD\uFF0C\u6216\u8005\u4E0A\u4F20\u6700\u8FD1\u4E00\u6B21\u89C1\u9762\u7684\u7167\u7247\u5427\u3002"],
    ["demo.4.title", "\u793A\u4F8B\u56DB\u6807\u9898", "\u8BFE\u672C\u91CC\u5939\u7740\u7684\uFF0C\u4E0D\u6B62\u662F\u4E66\u7B7E"],
    ["demo.4.body", "\u793A\u4F8B\u56DB\u6B63\u6587", "\u4E00\u5F20\u5C0F\u7EB8\u6761\uFF0C\u4E00\u7247\u79CB\u5929\u7684\u53F6\u5B50\uFF0C\u4E00\u53E5\u5199\u5728\u8BFE\u672C\u89D2\u843D\u91CC\u7684\u6084\u6084\u8BDD\u3002\n\n\u90A3\u65F6\u89C9\u5F97\u5FAE\u4E0D\u8DB3\u9053\uFF0C\u73B0\u5728\u60F3\u8D77\u6765\u5374\u683C\u5916\u73CD\u8D35\u3002"],
    ["demo.nickname", "\u793A\u4F8B\u4F5C\u8005", "\u65F6\u5149\u5C0F\u90AE\u5DEE"],
    ["demo.friends", "\u793A\u4F8B\u670B\u53CB", "\u8001\u670B\u53CB"]
  ]
};
var copyFields = Object.fromEntries(Object.entries(sections).flatMap(([group, fields]) => fields.map(([key, label, value]) => [key, { group, label, value }])));

// lib/media-format.ts
var formats = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "audio/mpeg": "mp3", "audio/mp4": "m4a" };
function parseCatalog(value) {
  const fail = () => {
    throw new ApiError("\u56FE\u5E93\u6587\u4EF6\u683C\u5F0F\u4E0D\u6B63\u786E\uFF0C\u8BF7\u91CD\u65B0\u4F7F\u7528\u6253\u5305\u52A9\u624B\u751F\u6210\u4E0A\u4F20\u5305\u3002", 503);
  };
  if (!value || typeof value !== "object") return fail();
  const input = value;
  if (input.version !== 1 || !Array.isArray(input.files) || input.files.length > 900 || typeof input.backgroundId !== "string") return fail();
  const seen = /* @__PURE__ */ new Set();
  const files = input.files.map((item) => {
    if (!item || typeof item !== "object") return fail();
    const f = item;
    if (!/^f-[a-f0-9]{32}$/.test(f.id) || seen.has(f.id) || !Object.hasOwn(formats, f.kind) || f.path !== `/_album_media/${f.id}.${formats[f.kind]}` || typeof f.name !== "string" || !f.name.trim() || f.name.length > 180 || !Number.isSafeInteger(f.size) || f.size < 1 || f.size > (f.kind.startsWith("image/") ? 10 : 20) * 1024 * 1024) return fail();
    seen.add(f.id);
    return { id: f.id, path: f.path, name: f.name, kind: f.kind, size: f.size };
  });
  if (files.reduce((sum, file) => sum + file.size, 0) > 200 * 1024 * 1024) return fail();
  if (input.backgroundId && !files.some((file) => file.id === input.backgroundId && file.kind.startsWith("audio/"))) return fail();
  return { version: 1, files, backgroundId: input.backgroundId };
}

// lib/server.ts
var defaults = { title: "\u65F6\u5149\u7EAA\u5FF5\u518C", welcome: "\u628A\u6563\u843D\u5728\u5C81\u6708\u91CC\u7684\u6211\u4EEC\uFF0C\u91CD\u65B0\u6536\u85CF\u5728\u4E00\u8D77\u3002", showExamples: "true", accessVersion: "1" };
var noCache = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { ...noCache, "Content-Type": "application/json; charset=utf-8" } });
}
function runtime(env) {
  if (!env.DB || !env.ASSETS || !(env.ALBUM_CODES || env.ALBUM_CODE) || !env.ADMIN_CODE || !env.APP_SECRET) {
    console.error("Missing binding names:", [["DB", !!env.DB], ["ASSETS", !!env.ASSETS], ["ALBUM_CODES", !!(env.ALBUM_CODES || env.ALBUM_CODE)], ["ADMIN_CODE", !!env.ADMIN_CODE], ["APP_SECRET", !!env.APP_SECRET]].filter(([, present]) => !present).map(([key]) => key).join(","));
    throw new ApiError("\u7EAA\u5FF5\u518C\u6B63\u5728\u914D\u7F6E\u4E2D\uFF0C\u8BF7\u68C0\u67E5 D1 \u7ED1\u5B9A\u548C\u4E09\u4E2A\u79D8\u5BC6\u53D8\u91CF\u3002", 503);
  }
  return env;
}
async function settings(env) {
  const { results } = await env.DB.prepare("SELECT key,value FROM settings").all();
  return { ...defaults, ...Object.fromEntries(results.map((x) => [x.key, x.value])) };
}
function backgroundId(s, catalog) {
  const id = s.backgroundMediaId ?? catalog.backgroundId;
  return catalog.files.some((file) => file.id === id && file.kind.startsWith("audio/")) ? id : "";
}
function displaySettings(s, catalog) {
  let copy = {};
  try {
    copy = JSON.parse(s.copy || "{}");
  } catch {
  }
  const backgroundMediaId = backgroundId(s, catalog);
  return { title: s.title, welcome: s.welcome, showExamples: s.showExamples === "true", hasBackground: !!backgroundMediaId, backgroundMediaId, copy };
}
async function loadCatalog(request, env) {
  const response = await env.ASSETS.fetch(new Request(new URL("/_album_media/catalog.json", request.url)));
  if (!response.ok || !response.headers.get("Content-Type")?.includes("application/json")) throw new ApiError("\u56FE\u5E93\u5C1A\u672A\u6253\u5305\uFF0C\u8BF7\u91CD\u65B0\u4E0A\u4F20\u5B8C\u6574\u90E8\u7F72\u5305\u3002", 503);
  return parseCatalog(await response.json());
}
async function packedMedia(request, env, file) {
  let range;
  try {
    const value = request.headers.get("Range");
    if (value) range = parseRange(value, file.size);
  } catch {
    return new Response(null, { status: 416, headers: { ...noCache, "Content-Range": "bytes */" + file.size } });
  }
  const headers = new Headers();
  if (range) headers.set("Range", `bytes=${range.offset}-${range.offset + range.length - 1}`);
  const result = await env.ASSETS.fetch(new Request(new URL(file.path, request.url), { method: "GET", headers }));
  if (![200, 206, 416].includes(result.status) || result.headers.get("Content-Type")?.includes("text/html")) throw new ApiError("\u8FD9\u4EFD\u7167\u7247\u6216\u97F3\u4E50\u6CA1\u6709\u5305\u542B\u5728\u5F53\u524D\u4E0A\u4F20\u5305\u4E2D\uFF0C\u8BF7\u91CD\u65B0\u6253\u5305\u65F6\u4FDD\u7559\u539F\u6709\u6587\u4EF6\u3002", 404);
  const output = new Headers(result.headers);
  for (const [key, value] of Object.entries(noCache)) output.set(key, value);
  output.set("Content-Type", file.kind);
  output.set("Content-Disposition", "inline");
  output.set("Accept-Ranges", "bytes");
  if (range && result.status !== 416) {
    output.set("Content-Range", `bytes ${range.offset}-${range.offset + range.length - 1}/${file.size}`);
    output.set("Content-Length", String(range.length));
    return new Response(result.status === 206 ? result.body : result.body ? sliceBody(result.body, range.offset, range.length) : null, { status: 206, headers: output });
  }
  if (result.status === 200) output.set("Content-Length", String(file.size));
  return new Response(result.body, { status: result.status, headers: output });
}
function sliceBody(body, offset, length) {
  const reader = body.getReader();
  let skipped = offset, remaining = length;
  return new ReadableStream({ async pull(controller) {
    try {
      while (remaining > 0) {
        const { value, done } = await reader.read();
        if (done) {
          controller.error(new Error("\u5A92\u4F53\u6587\u4EF6\u4E0D\u5B8C\u6574\u3002"));
          return;
        }
        if (skipped >= value.byteLength) {
          skipped -= value.byteLength;
          continue;
        }
        const bytes = value.subarray(skipped, Math.min(value.byteLength, skipped + remaining));
        skipped = 0;
        remaining -= bytes.byteLength;
        controller.enqueue(bytes);
        if (!remaining) {
          await reader.cancel();
          controller.close();
        }
        return;
      }
    } catch (error) {
      controller.error(error);
    }
  }, cancel(reason) {
    return reader.cancel(reason);
  } });
}
async function current(request, env, s) {
  const token = cookieValue(request, "album_session");
  if (!token) return null;
  const session = await env.DB.prepare("SELECT * FROM sessions WHERE token_hash=?").bind(await digest(token)).first();
  return session && session.expires > Date.now() && session.version === Number(s.accessVersion) ? session : null;
}
function requireAdmin(session) {
  if (session.role !== "admin") throw new ApiError("\u8FD9\u9879\u64CD\u4F5C\u9700\u8981\u7BA1\u7406\u53E3\u4EE4\u3002", 403);
}
async function login(request, env, s, catalog, adminOnly = false) {
  const ip = await digest(env.APP_SECRET + ":ip:" + (request.headers.get("CF-Connecting-IP") || "local"));
  const attempt = await env.DB.prepare("SELECT count,expires FROM attempts WHERE key=?").bind(ip).first();
  if (attempt && attempt.expires > Date.now() && attempt.count >= 8) throw new ApiError("\u53E3\u4EE4\u5C1D\u8BD5\u6B21\u6570\u8F83\u591A\uFF0C\u8BF7 15 \u5206\u949F\u540E\u518D\u8BD5\u3002", 429);
  const input = await request.json();
  const code = text(input.code, 128, true);
  const hash = await digest(env.APP_SECRET + ":code:" + code), admin = safeEqual(hash, await digest(env.APP_SECRET + ":code:" + env.ADMIN_CODE));
  const hashes = s.accessHashes ? JSON.parse(s.accessHashes) : s.accessHash ? [s.accessHash] : await Promise.all(configuredAccessCodes(env).map((code2) => digest(env.APP_SECRET + ":code:" + code2)));
  const visitor = hashes.reduce((matched, expected) => safeEqual(hash, expected) || matched, false);
  const good = admin || !adminOnly && visitor;
  if (!good) {
    await env.DB.prepare("INSERT INTO attempts(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires<? THEN 1 ELSE count+1 END, expires=CASE WHEN expires<? THEN excluded.expires ELSE expires END").bind(ip, Date.now() + 9e5, Date.now(), Date.now()).run();
    throw new ApiError(adminOnly ? "\u7BA1\u7406\u53E3\u4EE4\u4E0D\u6B63\u786E\u3002" : "\u53E3\u4EE4\u4E0D\u6B63\u786E\uFF0C\u518D\u60F3\u60F3\u6211\u4EEC\u4E4B\u95F4\u7684\u6697\u53F7\u3002", 401);
  }
  const prior = cookieValue(request, "album_author");
  let author = prior ? await env.DB.prepare("SELECT id FROM authors WHERE token_hash=?").bind(await digest(prior)).first() : null;
  let authorToken = prior;
  if (!author) {
    authorToken = randomToken();
    author = { id: crypto.randomUUID() };
    await env.DB.prepare("INSERT INTO authors(id,token_hash) VALUES(?,?)").bind(author.id, await digest(authorToken)).run();
  }
  const token = randomToken();
  const old = cookieValue(request, "album_session");
  const statements = [env.DB.prepare("INSERT INTO sessions(token_hash,author_id,role,expires,version) VALUES(?,?,?,?,?)").bind(await digest(token), author.id, admin ? "admin" : "visitor", Date.now() + 7 * 864e5, Number(s.accessVersion)), env.DB.prepare("DELETE FROM attempts WHERE key=? OR expires<?").bind(ip, Date.now()), env.DB.prepare("DELETE FROM sessions WHERE expires<?").bind(Date.now())];
  if (old) statements.push(env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(old)));
  await env.DB.batch(statements);
  const response = json({ authenticated: true, role: admin ? "admin" : "visitor", settings: displaySettings(s, catalog) });
  response.headers.append("Set-Cookie", cookie(request, "album_session", token, 7));
  response.headers.append("Set-Cookie", cookie(request, "album_author", authorToken, 365));
  return response;
}
function expose(row, assets, session) {
  return { id: row.id, title: row.title, body: row.body, category: row.category, nickname: row.nickname, happenedAt: row.happened_at, tags: JSON.parse(row.tags), createdAt: row.created_at, updatedAt: row.updated_at, canEdit: session.role === "admin" || row.author_id === session.author_id, canDelete: session.role === "admin", assets: assets.map((a) => ({ id: a.id, mediaId: a.object_key.startsWith("pack:") ? a.object_key.slice(5) : void 0, kind: a.kind, url: "/api/media/" + a.id, size: a.size })) };
}
async function list(env, session) {
  const [{ results: rows }, { results: files }] = await Promise.all([env.DB.prepare("SELECT * FROM memories ORDER BY COALESCE(NULLIF(happened_at,''),substr(created_at,1,10)) DESC,created_at DESC").all(), env.DB.prepare("SELECT * FROM assets WHERE memory_id IS NOT NULL ORDER BY position").all()]);
  return json({ memories: rows.map((row) => expose(row, files.filter((a) => a.memory_id === row.id), session)) });
}
async function save(request, env, session, catalog, id) {
  const old = id ? await env.DB.prepare("SELECT * FROM memories WHERE id=?").bind(id).first() : null;
  if (id && !old) throw new ApiError("\u8FD9\u6761\u56DE\u5FC6\u5DF2\u4E0D\u5B58\u5728\u3002", 404);
  if (old && old.author_id !== session.author_id && session.role !== "admin") throw new ApiError("\u53EA\u80FD\u7F16\u8F91\u81EA\u5DF1\u53D1\u5E03\u7684\u56DE\u5FC6\u3002", 403);
  const form = await boundedForm(request), data = validateMemory(Object.fromEntries(form.entries()));
  if ([...form.values()].some((value) => value instanceof File && value.size)) throw new ApiError("\u7167\u7247\u548C\u97F3\u4E50\u8BF7\u5148\u7528\u6253\u5305\u52A9\u624B\u52A0\u5165\u7F51\u7AD9\uFF0C\u518D\u4ECE\u56FE\u5E93\u9009\u62E9\u3002");
  if (old && form.get("revision") && form.get("revision") !== old.updated_at) throw new ApiError("\u8FD9\u6761\u56DE\u5FC6\u521A\u521A\u88AB\u4FEE\u6539\uFF0C\u8BF7\u91CD\u65B0\u6253\u5F00\u540E\u518D\u7F16\u8F91\u3002", 409);
  const existing = old ? (await env.DB.prepare("SELECT * FROM assets WHERE memory_id=? ORDER BY position").bind(old.id).all()).results : [];
  let keepIds = [], mediaIds = [];
  try {
    keepIds = JSON.parse(String(form.get("keepAssets") || "[]"));
    mediaIds = JSON.parse(String(form.get("mediaIds") || "[]"));
  } catch {
    throw new ApiError("\u9644\u4EF6\u9009\u62E9\u65E0\u6548\u3002");
  }
  if (!Array.isArray(keepIds) || keepIds.length > 10 || keepIds.some((id2) => typeof id2 !== "string" || !existing.some((asset) => asset.id === id2)) || new Set(keepIds).size !== keepIds.length) throw new ApiError("\u9644\u4EF6\u9009\u62E9\u65E0\u6548\u3002");
  if (!Array.isArray(mediaIds) || mediaIds.length > 10 || mediaIds.some((id2) => typeof id2 !== "string" || !catalog.files.some((file) => file.id === id2)) || new Set(mediaIds).size !== mediaIds.length) throw new ApiError("\u8BF7\u9009\u62E9\u5F53\u524D\u56FE\u5E93\u4E2D\u7684\u7167\u7247\u548C\u97F3\u4E50\u3002");
  const kept = existing.filter((asset) => keepIds.includes(asset.id));
  const added = mediaIds.map((id2) => catalog.files.find((file) => file.id === id2));
  if (added.some((file) => kept.some((asset) => asset.object_key === "pack:" + file.id))) throw new ApiError("\u540C\u4E00\u6761\u56DE\u5FC6\u4E0D\u80FD\u91CD\u590D\u9009\u62E9\u540C\u4E00\u4E2A\u6587\u4EF6\u3002");
  const kinds = [...kept.map((asset) => asset.kind), ...added.map((file) => file.kind)];
  if (kinds.filter((kind) => kind.startsWith("image/")).length > 9) throw new ApiError("\u6BCF\u6761\u56DE\u5FC6\u6700\u591A 9 \u5F20\u7167\u7247\u3002");
  if (kinds.filter((kind) => kind.startsWith("audio/")).length > 1) throw new ApiError("\u6BCF\u6761\u56DE\u5FC6\u6700\u591A\u6DFB\u52A0\u4E00\u9996\u97F3\u4E50\u3002");
  if (!data.body && !kinds.length) throw new ApiError("\u5199\u4E00\u6BB5\u56DE\u5FC6\uFF0C\u6216\u4ECE\u56FE\u5E93\u9009\u62E9\u7167\u7247\u3001\u97F3\u4E50\u5427\u3002");
  const memoryId = id || crypto.randomUUID(), now = (/* @__PURE__ */ new Date()).toISOString(), statements = [];
  if (old) statements.push(env.DB.prepare("UPDATE memories SET nickname=?,title=?,body=?,category=?,happened_at=?,tags=?,updated_at=? WHERE id=?").bind(data.nickname, data.title, data.body, data.category, data.happenedAt, JSON.stringify(data.tags), now, memoryId));
  else statements.push(env.DB.prepare("INSERT INTO memories(id,author_id,nickname,title,body,category,happened_at,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(memoryId, session.author_id, data.nickname, data.title, data.body, data.category, data.happenedAt, JSON.stringify(data.tags), now, now));
  for (const [position, asset] of kept.entries()) statements.push(env.DB.prepare("UPDATE assets SET position=? WHERE id=?").bind(position, asset.id));
  for (const [position, file] of added.entries()) statements.push(env.DB.prepare("INSERT INTO assets(id,memory_id,object_key,kind,size,position) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(), memoryId, "pack:" + file.id, file.kind, file.size, kept.length + position));
  for (const asset of existing.filter((asset2) => !keepIds.includes(asset2.id))) statements.push(env.DB.prepare("DELETE FROM assets WHERE id=?").bind(asset.id));
  await env.DB.batch(statements);
  return json({ id: memoryId }, old ? 200 : 201);
}
async function remove(env, session, id) {
  requireAdmin(session);
  const row = await env.DB.prepare("SELECT id FROM memories WHERE id=?").bind(id).first();
  if (!row) throw new ApiError("\u56DE\u5FC6\u5DF2\u4E0D\u5B58\u5728\u3002", 404);
  await env.DB.batch([env.DB.prepare("DELETE FROM assets WHERE memory_id=?").bind(id), env.DB.prepare("DELETE FROM memories WHERE id=?").bind(id)]);
  return json({ ok: true });
}
async function media(request, env, asset, catalog) {
  const file = catalog.files.find((file2) => "pack:" + file2.id === asset.object_key);
  if (!file) throw new ApiError("\u8FD9\u4EFD\u7167\u7247\u6216\u97F3\u4E50\u4E0D\u5728\u5F53\u524D\u4E0A\u4F20\u5305\u91CC\uFF0C\u8BF7\u91CD\u65B0\u6253\u5305\u65F6\u5BFC\u5165\u4E0A\u6B21\u7684\u4E0A\u4F20\u5305\u3002", 404);
  return packedMedia(request, env, file);
}
async function updateSettings(request, env, session, s, catalog) {
  requireAdmin(session);
  const input = await request.json();
  const values = {};
  if (input.backgroundMediaId !== void 0) {
    if (typeof input.backgroundMediaId !== "string" || input.backgroundMediaId && !catalog.files.some((file) => file.id === input.backgroundMediaId && file.kind.startsWith("audio/"))) throw new ApiError("\u8BF7\u9009\u62E9\u56FE\u5E93\u4E2D\u7684\u97F3\u4E50\u3002");
    values.backgroundMediaId = input.backgroundMediaId;
  }
  if (input.title !== void 0) values.title = text(input.title, 40, true);
  if (input.welcome !== void 0) values.welcome = text(input.welcome, 200);
  if (input.showExamples !== void 0) {
    if (typeof input.showExamples !== "boolean") throw new ApiError("\u8BBE\u7F6E\u683C\u5F0F\u4E0D\u6B63\u786E\u3002");
    values.showExamples = String(input.showExamples);
  }
  if (input.copy !== void 0) {
    if (!input.copy || typeof input.copy !== "object" || Array.isArray(input.copy)) throw new ApiError("\u6587\u5B57\u8BBE\u7F6E\u683C\u5F0F\u4E0D\u6B63\u786E\u3002");
    const clean = {};
    for (const [key, value] of Object.entries(input.copy)) {
      if (!Object.hasOwn(copyFields, key) || typeof value !== "string" || value.length > 5e3) throw new ApiError("\u6587\u5B57\u8BBE\u7F6E\u5305\u542B\u65E0\u6548\u5B57\u6BB5\uFF0C\u6216\u5355\u6BB5\u5185\u5BB9\u8D85\u8FC7 5000 \u5B57\u3002");
      clean[key] = value;
    }
    if (JSON.stringify(clean).length > 18e4) throw new ApiError("\u6587\u5B57\u8BBE\u7F6E\u5185\u5BB9\u8FC7\u957F\u3002");
    values.copy = JSON.stringify(clean);
  }
  if (input.accessCodes !== void 0 || input.accessCode !== void 0 && input.accessCode !== "") {
    const codes = accessCodes(input.accessCodes !== void 0 ? input.accessCodes : [input.accessCode]);
    const adminHash = await digest(env.ADMIN_CODE);
    for (const code of codes) if (safeEqual(await digest(code), adminHash)) throw new ApiError("\u8BBF\u95EE\u53E3\u4EE4\u4E0D\u80FD\u4E0E\u7BA1\u7406\u53E3\u4EE4\u76F8\u540C\u3002");
    values.accessHashes = JSON.stringify(await Promise.all(codes.map((code) => digest(env.APP_SECRET + ":code:" + code))));
    values.accessVersion = String(Number(s.accessVersion) + 1);
  }
  const statements = Object.entries(values).map(([k, v]) => env.DB.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k, v));
  if (values.accessVersion) {
    statements.push(env.DB.prepare("DELETE FROM sessions WHERE token_hash<>?").bind(session.token_hash));
    statements.push(env.DB.prepare("UPDATE sessions SET version=? WHERE token_hash=?").bind(Number(values.accessVersion), session.token_hash));
  }
  if (statements.length) await env.DB.batch(statements);
  return json({ ok: true, settings: displaySettings({ ...s, ...values }, catalog) });
}
async function background() {
  throw new ApiError("\u97F3\u4E50\u8BF7\u5148\u7528\u6253\u5305\u52A9\u624B\u52A0\u5165\u7F51\u7AD9\uFF0C\u518D\u5728\u540E\u53F0\u9009\u62E9\u3002");
}
async function guestMessages(request, env, session, id) {
  if (request.method === "GET" && !id) {
    const { results } = await env.DB.prepare("SELECT id,nickname,body,updated_at AS updatedAt FROM messages ORDER BY created_at ASC,id ASC").all();
    return json({ messages: results });
  }
  if (request.method === "DELETE" && id) {
    requireAdmin(session);
    const result = await env.DB.prepare("DELETE FROM messages WHERE id=?").bind(id).run();
    if (!result.meta.changes) throw new ApiError("\u8FD9\u6761\u7559\u8A00\u5DF2\u4E0D\u5B58\u5728\u3002", 404);
    return json({ ok: true });
  }
  if (request.method === "POST" && !id || request.method === "PATCH" && id) {
    if (id) requireAdmin(session);
    const input = await request.json(), nickname = text(input.nickname, 30, true), body = text(input.body, 1e3, true), now = (/* @__PURE__ */ new Date()).toISOString();
    if (id) {
      const result = await env.DB.prepare("UPDATE messages SET nickname=?,body=?,updated_at=? WHERE id=? AND updated_at=?").bind(nickname, body, now, id, text(input.revision, 50, true)).run();
      if (!result.meta.changes) throw new ApiError("\u7559\u8A00\u5DF2\u88AB\u4FEE\u6539\u6216\u5220\u9664\uFF0C\u8BF7\u5237\u65B0\u540E\u91CD\u8BD5\u3002", 409);
    } else {
      const recent = await env.DB.prepare("SELECT count(*) AS total FROM messages WHERE author_id=? AND created_at>?").bind(session.author_id, new Date(Date.now() - 6e4).toISOString()).first();
      if ((recent?.total || 0) >= 5) throw new ApiError("\u7559\u8A00\u5DF2\u6536\u5230\uFF0C\u8BF7\u7A0D\u7B49\u7247\u523B\u518D\u53D1\u9001\u3002", 429);
      id = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO messages(id,author_id,nickname,body,created_at,updated_at) VALUES(?,?,?,?,?,?)").bind(id, session.author_id, nickname, body, now, now).run();
    }
    return json({ id }, request.method === "POST" ? 201 : 200);
  }
  throw new ApiError("\u6CA1\u6709\u627E\u5230\u8FD9\u4E2A\u5165\u53E3\u3002", 404);
}
async function handleApi(request, path, bindings) {
  try {
    if (!["GET", "HEAD"].includes(request.method) && request.headers.get("Origin") !== new URL(request.url).origin) throw new ApiError("\u8BF7\u4ECE\u7EAA\u5FF5\u518C\u9875\u9762\u63D0\u4EA4\u64CD\u4F5C\u3002", 403);
    const env = runtime(bindings), catalog = await loadCatalog(request, env), s = await settings(env), session = await current(request, env, s), method = request.method;
    if (path[0] === "session" && method === "GET") return json({ authenticated: !!session, role: session?.role, settings: displaySettings(s, catalog) });
    if (path[0] === "login" && method === "POST") return await login(request, env, s, catalog);
    if (path[0] === "admin" && method === "POST") return await login(request, env, s, catalog, true);
    if (!session) throw new ApiError("\u8BF7\u5148\u8F93\u5165\u53E3\u4EE4\uFF0C\u6253\u5F00\u6211\u4EEC\u7684\u7EAA\u5FF5\u518C\u3002", 401);
    if (path[0] === "logout" && method === "POST") {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(session.token_hash).run();
      const response = json({ ok: true });
      response.headers.append("Set-Cookie", cookie(request, "album_session", "", 0));
      return response;
    }
    if (path[0] === "catalog" && method === "GET") return json({ files: catalog.files.map(({ id, name, kind, size }) => ({ id, name, kind, size, url: "/api/packed/" + id })) });
    if (path[0] === "packed" && path[1] && method === "GET") {
      const file = catalog.files.find((file2) => file2.id === path[1]);
      if (!file) throw new ApiError("\u6587\u4EF6\u672A\u627E\u5230\u3002", 404);
      return await packedMedia(request, env, file);
    }
    if (path[0] === "memories") {
      if (!path[1] && method === "GET") return await list(env, session);
      if (!path[1] && method === "POST") return await save(request, env, session, catalog);
      if (path[1] && method === "PATCH") return await save(request, env, session, catalog, path[1]);
      if (path[1] && method === "DELETE") return await remove(env, session, path[1]);
    }
    if (path[0] === "messages") return await guestMessages(request, env, session, path[1]);
    if (path[0] === "media" && path[1] && method === "GET") {
      const asset = await env.DB.prepare("SELECT * FROM assets WHERE id=?").bind(path[1]).first();
      if (!asset) throw new ApiError("\u6587\u4EF6\u672A\u627E\u5230\u3002", 404);
      return await media(request, env, asset, catalog);
    }
    if (path[0] === "music" && method === "GET") {
      const file = catalog.files.find((file2) => file2.id === backgroundId(s, catalog));
      if (!file) throw new ApiError("\u8FD8\u6CA1\u6709\u6DFB\u52A0\u80CC\u666F\u97F3\u4E50\u3002", 404);
      return await packedMedia(request, env, file);
    }
    if (path[0] === "settings" && method === "PATCH") return await updateSettings(request, env, session, s, catalog);
    if (path[0] === "background" && method === "POST") {
      requireAdmin(session);
      return await background();
    }
    throw new ApiError("\u6CA1\u6709\u627E\u5230\u8FD9\u4E2A\u5165\u53E3\u3002", 404);
  } catch (error) {
    if (error instanceof ApiError) return json({ error: error.message }, error.status);
    if (error instanceof SyntaxError) return json({ error: "\u63D0\u4EA4\u7684\u5185\u5BB9\u683C\u5F0F\u4E0D\u6B63\u786E\u3002" }, 400);
    console.error("Album request failed:", error instanceof Error ? error.message : "unknown");
    return json({ error: "\u6682\u65F6\u6CA1\u80FD\u5B8C\u6210\u64CD\u4F5C\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002" }, 500);
  }
}

// src/worker.ts
var worker_default = {
  async fetch(request, env) {
    const pathname = new URL(request.url).pathname;
    let normalized = pathname;
    try {
      for (let i = 0; i < 3; i++) {
        normalized = decodeURIComponent(normalized);
        if (normalized.replace(/\\/g, "/").split("/").includes("_album_media")) return new Response(null, { status: 404, headers: { "Cache-Control": "private, no-store" } });
        if (!normalized.includes("%")) break;
      }
    } catch {
      return new Response(null, { status: 404 });
    }
    if (!pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    const response = await handleApi(request, pathname.slice(5).split("/").filter(Boolean), env);
    if (request.body && !request.bodyUsed) {
      const length = Number(request.headers.get("Content-Length") || 0);
      if (length > 0 && length <= 65536) await request.arrayBuffer().catch(() => {
      });
      else await request.body.cancel().catch(() => {
      });
    }
    return response;
  }
};
export {
  worker_default as default
};
