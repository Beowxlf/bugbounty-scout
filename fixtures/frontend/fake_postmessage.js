window.addEventListener("message", (event) => {
  const action = event.data.action;
  if (action === "billing") console.log(event.data);
});
window.parent.postMessage({ token: "fake-message-token" }, "*");
