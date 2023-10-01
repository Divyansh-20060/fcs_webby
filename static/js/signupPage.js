
function handleSignupClick() {
    // Change the URL in the address bar

    // window.location.href = '/buyerHome';  // Replace with the actual URL of your new page

    // const formData = new FormData();
    // Get the values from the username and password text boxes
    const name_tb = document.getElementById('name_tb').value;
    const username = document.getElementById('username_tb').value;
    const password = document.getElementById('password_tb').value;
    const user_type = document.getElementById('dropdown').value;
    const file_input = document.getElementById('file-input').value;
    // Create a data object to send to the server
    const data = {
        name_tb: name_tb,
        username: username,
        password: password,
        user_type: user_type,
        "file" : file_input,
    };
    // formData.append(name_tb, name_tb);
    // formData.append(username, username);
    // formData.append(password, password);
    // formData.append(user_type, user_type);

    // Send a POST request to the server with the login data
    fetch('/signupCheck/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
        // body: formData

    })
    .then(response => response.json()) // Assuming the server responds with JSON
    .then(responseData => {
        // Check the server's response for login success
        if (responseData.success) {
            // Login was successful
            // You can do client-side work here
            console.log('signup successful');
            window.location.href = '/mainWelcome';
            alert("Signed Up Successfully");
            // Redirect to a new page, show a success message, etc.
        } else {
            // Login failed
            console.error('sign up failed:', responseData.error);
            alert("username already exists");
            // Display an error message to the user
        }
    })
    .catch(error => {
        // Handle any errors that occurred during the fetch
        console.error('Fetch error:', error);
    });
}
