// Assuming you have a button with ID "login-button"
const loginButton = document.getElementById('login-submit');

// Add a click event listener to the button
loginButton.addEventListener('click', function() {
    // Get the values from the username and password text boxes
    const username = document.getElementById('username_tb').value;
    const password = document.getElementById('password_tb').value;

    // Create a data object to send to the server
    const data = {
        username: username,
        password: password
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
            handleSubmitClick()
            // Redirect to a new page, show a success message, etc.
        } else {
            // Login failed
            console.error('Login failed:', responseData.error);
            // Display an error message to the user
        }
    })
    .catch(error => {
        // Handle any errors that occurred during the fetch
        console.error('Fetch error:', error);
    });
});

function handleSubmitClick() {
    // Change the URL in the address bar
    window.location.href = '/mainPage';  // Replace with the actual URL of your new page
}