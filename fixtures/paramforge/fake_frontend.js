const adminBillingRoute = "/api/v1/admin/billing/invoices/export";
const runtimeConfig = { organizationId: "public-org", uploadEndpoint: "/files/upload" };
localStorage.setItem("activeAccountId", "public-id");
sessionStorage.getItem("debugPanel");
document.cookie = "themePreference=dark";
fetch("/api/v1/users/search", { headers: { "X-Client-Version": "1" } });
const query = `query AccountMembers($accountId: ID!) { accountMembers }`;
