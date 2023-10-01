// function handleSignupClick() {
//     console.log("hello");
// }

function handleSignupClick() {
    // Change the URL in the address bar

    alert("something happened");

    const form = document.getElementById("getstuff");

    const formData = new FormData(form);
    console.log(formData.entries());
    for (var [key, value] of formData.entries()) { 
        console.log(key, value);
    }
    alert("something happened again");
    fetch("/upload_pdf/", {
        method: "POST",
        body: formData,
    })
    .then((response) => response.json())
    .then((data) => {
        // Handle the response from the server
        console.log(data);
    })
    .catch((error) => {
        console.error("Error:", error);
    });

    // // Get the values from the username and password text boxes
    // const name_tb = document.getElementById('name_tb').value;
    // const username = document.getElementById('username_tb').value;
    // const password = document.getElementById('password_tb').value;
    // const user_type = document.getElementById('dropdown').value;
    // const data = {
    //     name_tb: name_tb,
    //     username: username,
    //     password: password,
    //     user_type: user_type,
    // };


    // // Send a POST request to the server with the login data
    // fetch('/signupCheck/', {
    //     method: 'POST',
    //     headers: {
    //         'Content-Type': 'application/json'
    //     },
    //     body: JSON.stringify(data)

    // })
    // .then(response => response.json()) // Assuming the server responds with JSON
    // .then(responseData => {
    //     // Check the server's response for login success
    //     if (responseData.success) {
    //         // Login was successful
    //         // You can do client-side work here
    //         console.log('signup successful');
    //         window.location.href = '/mainWelcome';
    //         alert("Signed Up Successfully");
    //         // Redirect to a new page, show a success message, etc.
    //     } else {
    //         // Login failed
    //         console.error('sign up failed:', responseData.error);
    //         alert("username already exists");
    //         // Display an error message to the user
    //     }
    // })
    // .catch(error => {
    //     // Handle any errors that occurred during the fetch
    //     console.error('Fetch error:', error);
    // });
}