// function viewProfileButton(){
//     window.location.href = '/sellerProfile';
// }

const seller_uname = localStorage.getItem("uname");

const uname_header = document.getElementById("uname"); 
uname_header.innerText = "seller uname: " + seller_uname;

const viewListingsButton = document.getElementById("viewListingsButton");

viewListingsButton.addEventListener("click", function () {
    // Get the seller's name and any other necessary data
    const sellerName = "Seller Name"; // Replace with the actual seller's name
    const sellerUsername = seller_uname;

    // Construct the URL with query parameters
    const url = `listings.html?sellerName=${encodeURIComponent(sellerName)}&sellerUsername=${encodeURIComponent(sellerUsername)}`;
    window.location.href = url;
});