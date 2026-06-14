const endpoint = "https://api.example.test/api/graphql";
const query = `subscription AccountChanged($accountId: ID!) { accountChanged(accountId: $accountId) { account owner email } }`;
fetch(endpoint, {method: "POST", headers: {Authorization: "Bearer fake-token"}});
