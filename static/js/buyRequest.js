document.addEventListener("DOMContentLoaded", function () {
    // Fetch the JSON data from listings.json
    fetch("listings.json")
        .then((response) => response.json())
        .then((data) => {
            const requestsContainer = document.getElementById("requestsContainer");

            // Iterate through all sellers and their listings
            data.forEach((seller) => {
                // Iterate through the listings of the seller
                seller.listings.forEach((listing) => {
                    const listingItem = document.createElement("div");
                    listingItem.innerHTML = `
                        <h2>Title: ${listing.title}</h2>
                        <p>Description: ${listing.description}</p>
                        <button onclick="requestListing('${seller.sellerUsername}', '${listing.title}')">Request Listing</button>
                        <button onclick="buyListing('${seller.sellerUsername}', '${listing.title}')">Buy Listing</button>
                    `;
                    requestsContainer.appendChild(listingItem);
                });
            });
        })
        .catch((error) => {
            console.error("Error fetching or parsing JSON data: " + error);
        });
});

// Function to handle requesting a listing
function requestListing(sellerUsername, listingTitle) {
    // Implement your logic to send a request to the seller
    // You can update the JSON data to add the buyer's request to the respective listing.
    // Refresh the page or provide a success message to the buyer.
}

// Function to handle buying a listing
function buyListing(sellerUsername, listingTitle) {
    // Implement your logic to initiate the buying process
    // Update the JSON data to indicate that the listing is bought.
    // Refresh the page or provide a success message to the buyer.
}
