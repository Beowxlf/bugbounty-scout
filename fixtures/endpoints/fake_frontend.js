fetch("/api/users/123?include=roles");
axios.post("/admin/invite", { userId: "123" });
axios.get("https://api.example.test/v1/projects/abc123/files/999");
new WebSocket("wss://realtime.example.test/events");
new EventSource("/api/notifications");
const graph = "/graphql";
const upload = "/api/files/upload";
const config = { accountId: "fake", invoiceId: "fake" };
