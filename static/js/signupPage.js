const btn = document.getElementById("signup-submit");

btn.addEventListener(("click"), handleSignupClick);

function handleSignupClick() {
    alert("something happened");

    const form = document.getElementById("getstuff");

    const formData = new FormData(form);
    console.log(formData.entries());
    for (var [key, value] of formData.entries()) { 
        console.log(key, value);
    }
    alert("something happened again");
    fetch("/signupCheck/", {
        method: "POST",
        body: formData
    })
    .then((response) => response.json())
    .then((data) => {
        console.log(data);
        //window.location.href = '/loginPage';
        // Handle the response from the server
    })
    .catch((error) => {
        console.error("Error:", error);
    });
}