// for buyer
document.addEventListener("DOMContentLoaded", function () {
    // Fetch the JSON data from listings.json
    fetch("listings.json")
        .then((response) => response.json())
        .then((data) => {
            const listingsContainer = document.getElementById("listingsContainer");

            // Iterate through all sellers and their listings
            data.forEach((seller) => {
                const sellerNameHeader = document.createElement("h2");
                sellerNameHeader.textContent = `Seller: ${seller.sellerName}`;
                listingsContainer.appendChild(sellerNameHeader);

                // Iterate through the listings of the seller and create HTML elements to display them
                seller.listings.forEach((listing) => {
                    const listingItem = document.createElement("div");
                    listingItem.textContent = `Title: ${listing.title}, Description: ${listing.description}`;
                    listingsContainer.appendChild(listingItem);
                });
            });
        })
        .catch((error) => {
            console.error("Error fetching or parsing JSON data: " + error);
        });
});
