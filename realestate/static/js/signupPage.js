
function handleSignupClick() {
    const form = document.getElementById("getstuff");
    const formData = new FormData(form);
    fetch("/signupCheck/", {
        method: "POST",
        body: formData
    })
    .then(response => response.json())
    .then(responseData => {
        if (responseData.success){
            alert("signed up successfully");
            console.log('Signup successful');
            window.location.href = '/loginPage'; 
        } else{
            console.error('signup failed:', responseData.error);
            alert("user alredy exists");
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}