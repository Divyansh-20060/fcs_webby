function gotoLogin() {
    // Change the URL in the address bar
    window.location.href = '/buyerLogin';  // Replace with the actual URL of your new page
}

function gotoSignup() {
    // Change the URL in the address bar
    window.location.href = '/buyerSignup';  // Replace with the actual URL of your new page
}


//check if correct credentials are fed
function gotoHome() {

    // Get the values from the username and password text boxes
    const username = document.getElementById('username_tb').value;
    const password = document.getElementById('password_tb').value;
    const user_type = "buyer";
    // Create a data object to send to the server
    const data = {
        username: username,
        password: password,
        user_type: user_type,
    };

    // Send a POST request to the server with the login data
    fetch('/loginCheck/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json()) // Assuming the server responds with JSON
    .then(responseData => {
        // Check the server's response for login success
        if (responseData.success) {
            // Login was successful
            // You can do client-side work here
            console.log('Login successful');
            window.location.href = '/buyerHome';  // Replace with the actual URL of your new page
            // Redirect to a new page, show a success message, etc.
        } else {
            // Login failed
            console.error('Login failed:', responseData.error);
            alert("incorrect credentials")
            // Display an error message to the user
        }
    })
    .catch(error => {
        // Handle any errors that occurred during the fetch
        console.error('Fetch error:', error);
    });
}