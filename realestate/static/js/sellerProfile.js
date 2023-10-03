// function viewProfileButton(){
//     window.location.href = '/sellerProfile';
// }

const seller_uname = localStorage.getItem("uname");
const type = localStorage.getItem("user_type");

const uname_header = document.getElementById("uname"); 
const name_header = document.getElementById("name");
uname_header.innerText = "Seller Uname: " + seller_uname;


// id =  "/realestate/static/identity_docs/" + seller_uname + "_" + type + ".pdf"
// key =  "/realestate/static/public_keys/" + seller_uname + "_" + type + ".pem"
id =  "/static/identity_docs/" + seller_uname + "_" + type + ".pdf"
key =  "/static/public_keys/" + seller_uname + "_" + type + ".pem"


const id_btn = document.getElementById("download_id")
const key_btn = document.getElementById("download_pub_key")
id_btn.href = id
key_btn.href = key

const data = {
    "uname": seller_uname,
    "user_type": type,
    "requested": "name", 
};

// Send a POST request to the server with the login data
fetch('/queryDb/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
})
.then(response => response.json()) // Assuming the server responds with JSON
.then(responseData => {
    // Check the server's response for login success
    if (responseData.name) {
        name_header.innerText = "Seller Name: " + responseData.name;
    } else {
        console.log("cant get the user's name");
    }
})
.catch(error => {
    // Handle any errors that occurred during the fetch
    console.log('Fetch error:');
});




const viewListingsButton = document.getElementById("viewListingsButton");
viewListingsButton.addEventListener("click", function () {
    // Get the seller's name and any other necessary data
    const sellerName = "Seller Name"; // Replace with the actual seller's name
    const sellerUsername = seller_uname;

    // Construct the URL with query parameters
    const url = `listings.html?sellerName=${encodeURIComponent(sellerName)}&sellerUsername=${encodeURIComponent(sellerUsername)}`;
    window.location.href = url;
});