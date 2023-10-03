// for seller
document.addEventListener("DOMContentLoaded", function () {
    // Fetch the JSON data from listings.json
    fetch("listings.json")
        .then((response) => response.json())
        .then((data) => {
            // Retrieve the seller's username from the URL query parameters
            const urlParams = new URLSearchParams(window.location.search);
            const sellerUsername = urlParams.get("sellerUsername");

            // Find the seller's listings based on the sellerUsername
            const sellerListings = data.find((seller) => seller.sellerUsername === sellerUsername);

            if (sellerListings) {
                const listingsContainer = document.getElementById("listingsContainer");
                const sellerNameHeader = document.createElement("h2");
                sellerNameHeader.textContent = `Seller: ${sellerListings.sellerName}`;
                listingsContainer.appendChild(sellerNameHeader);

                // Iterate through the listings and create HTML elements to display them
                sellerListings.listings.forEach((listing) => {
                    const listingItem = document.createElement("div");
                    listingItem.textContent = `Title: ${listing.title}, Description: ${listing.description}`;
                    listingsContainer.appendChild(listingItem);
                });
            } else {
                console.error("Seller not found.");
            }
        })
        .catch((error) => {
            console.error("Error fetching or parsing JSON data: " + error);
        });
});
