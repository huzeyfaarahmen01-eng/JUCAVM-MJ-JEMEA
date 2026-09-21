const replyText = document.getElementById("reply-text");
const sendReply = document.getElementById("sendReply");
const conversation = document.querySelector("section.conversation");

sendReply.addEventListener("click", function () {

    const message = replyText.value.trim();

    if (message === "") {
        alert("Please write a reply first.");
        return;
    }

    const newMessage = document.createElement("div");

    newMessage.classList.add("admin-message");

    newMessage.innerHTML =` <strong>Jemea Admin</strong>
        <p>${message}</p>
        <small>Just now</small>
        `;
       
    

    conversation.appendChild(newMessage);

    // Save the message in the browser
   conversation.appendChild(newMessage);

let replies = JSON.parse(localStorage.getItem("adminReplies")) || [];

replies.push(message);

localStorage.setItem("adminReplies", JSON.stringify(replies));

replyText.value = "";

    replyText.value = "";

});
const savedReplies =
    JSON.parse(localStorage.getItem("adminReplies")) || [];

savedReplies.forEach(function (reply) {

    const savedMessage = document.createElement("div");

    savedMessage.classList.add("admin-message");

    savedMessage.innerHTML = `<strong>Jemea Admin</strong>
        <p>${reply}</p>
        <small>Saved message</small>`;
        
    

    conversation.appendChild(savedMessage);
});

if (savedReply) {

    const savedMessage = document.createElement("div");

    savedMessage.classList.add("admin-message");

    savedMessage.innerHTML = `  <strong>Jemea Admin</strong>
        <p>${savedReply}</p>
        <small>Saved message</small>`;
      
    

    conversation.appendChild(savedMessage);
}