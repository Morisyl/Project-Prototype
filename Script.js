document.addEventListener('DOMContentLoaded', function () {
    displayClients();
    showSection('home'); // Show the home section by default on page load
    shiftSectionsAutomatically(); // Start shifting through sections automatically

    // Function to check if the user is logged in by checking cookies
    async function checkLoginStatus() {
        try {
            const response = await fetch('/check-login', { method: 'GET', credentials: 'include' });

            if (response.ok) {
                const data = await response.json();
                toggleForms(data.loggedIn);
            } else {
                toggleForms(false);
            }
        } catch (error) {
            console.error('Error checking login status:', error);
            toggleForms(false);
        }
    }

    // Check if the user is logged in on page load
    checkLoginStatus();

   

    document.getElementById('login-form')?.addEventListener('submit', async function (event) {
        event.preventDefault();

        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include', // Include cookies in the request
                body: JSON.stringify({ email, password }),
            });

            if (response.ok) {
                showNotification('Login successful!', 'success');
                toggleForms(true);
                window.location.hash = '#home';
                showSection('home');
            } else {
                const data = await response.json();
                showNotification(data.message || 'Invalid username or password. Please try again.', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            showNotification('There was an error with your login. Please try again.', 'error');
        }
    });

    // Function to show a section based on ID
    function showSection(sectionId) {
        console.log("Showing section: " + sectionId);
        const sections = document.querySelectorAll('.section');
        sections.forEach(section => {
            section.id === sectionId ? section.classList.remove('hidden') : section.classList.add('hidden');
        });
    }

    // Function to check if user is logged in before showing certain sections
function checkLoginStatus(sectionId) {
    // Extract token from cookies
    const token = document.cookie.split('; ').find(row => row.startsWith('token='));

    // If a token exists, split and check if it is valid
    if (token && isValidToken(token.split('=')[1])) {
        // Show the requested section
        showSection(sectionId);
    } else {
        // Notify the user and show the registration section if not logged in
        showNotification("You need to log in to access this section.", 'error');
        showSection('register');
    }
}

// Helper function to validate JWT (adjust as per your actual validation logic)
function isValidToken(token) {
    // Here you would typically verify the token with a server or decode it
    try {
        const payload = JSON.parse(atob(token.split('.')[1])); // Decode JWT payload
        const expiry = payload.exp * 1000; // Token expiration time
        return Date.now() < expiry; // Check if the token has expired
    } catch (e) {
        console.error("Invalid token:", e);
        return false; // If decoding fails or token is invalid
    }
}


    // Event listener for the logout link click event
    document.getElementById('logout-link')?.addEventListener('click', async function (event) {
        event.preventDefault();

        // Call the logout function when the user clicks the logout link
        await logoutUser();
    });
});

 // Utility function to set a cookie with a specified expiration time
 function setCookie(name, value, minutes) {
    let expires = "";
    if (minutes) {
        const date = new Date();
        date.setTime(date.getTime() + (minutes * 60 * 1000)); // Convert minutes to milliseconds
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = `${name}=${value || ""}${expires}; path=/`;
}

// Utility function to get a cookie by name
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null; // Cookie not found
}


function userLoggedIn(token) {
    document.cookie = `userLoggedIn=true; path=/`; // Use cookies instead of localStorage
    document.cookie = `token=${token}; path=/; HttpOnly`;  // Store JWT token in a cookie
    document.getElementById('register-link').classList.add('hidden');
    document.getElementById('logout-link').classList.remove('hidden');
    showSection('home'); // Show home section
}

async function logoutUser() {
    try {
        // Make an API call to log out (blacklist token on the server-side)
        await fetch('/logout', {
            method: 'POST',
            credentials: 'include', // Include cookies
        });

        // Clear cookies and update UI after logging out
        document.cookie = 'userLoggedIn=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
        document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
        showNotification("You have been logged out.", 'success');
        toggleForms(false);

        // Redirect to the login section
        showSection('login');
    } catch (error) {
        console.error('Error during logout:', error);
        showNotification("There was an issue logging out. Please try again.", 'error');
    }
}

// Function to toggle forms based on login status
function toggleForms(isLoggedIn) {
    if (isLoggedIn) {
        document.getElementById('register-link').classList.add('hidden');
        document.getElementById('logout-link').classList.remove('hidden');
        showSection('home'); 
    } else {
        document.getElementById('logout-link').classList.add('hidden');
        document.getElementById('register-link').classList.remove('hidden');
        showSection('register');
    }
}

// Check for user login status on page load
document.addEventListener("DOMContentLoaded", function() {
    checkLoginStatus(); // Re-check login status on page load
});



 // Event listener for register form submission
document.getElementById('register-form')?.addEventListener('submit', async function (event) {
    event.preventDefault();
    
    // Retrieve form values
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const email = document.getElementById('register-email').value;

    // Basic frontend validation
    if (!username || !password || !email) {
        showNotification('Please fill in all fields.', 'error');
        return;
    }

    try {
        // Send registration data to server
        const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password, email }),
        });

        // Check if the response was successful
        if (response.ok) {
            const data = await response.json();
            showNotification(`Registration successful for ${username}. Welcome!`, 'success');
            // Redirect to login page after successful registration
            window.location.href = '#login'; // Redirect to login section
            showSection('login'); // Show the login section
        } else {
            // Handle server-side validation errors
            const errorData = await response.json();
            showNotification(errorData.error || 'Registration failed. Please try again.', 'error');
        }
    } catch (error) {
        // Handle network or unexpected errors
        console.error('Error:', error);
        showNotification('There was an error with your registration. Please try again.', 'error');
    }

    // Event listeners for login options
    document.getElementById('register-link')?.addEventListener('click', function (event) {
        event.preventDefault();
        showLoginOptions('register');
    });

    document.getElementById('login-link')?.addEventListener('click', function (event) {
        event.preventDefault();
        showLoginOptions('login');
    });

  // Initial section to show

    const loggedIn = document.cookie.split('; ').find(row => row.startsWith('userLoggedIn='));
    showSection(loggedIn && loggedIn.split('=')[1] === 'true' ? 'home' : 'logout');
});



// Function to check login status before showing section
function checkLoginStatus(sectionId) {
    const loggedIn = getCookie('userLoggedIn');
    
    if (loggedIn !== 'true') {
        showNotification('You must be logged in to access this section.', 'error');
        showSection('register'); // Redirect to registration if not logged in
        return false; // Indicate login check failed
    } else {
        showSection(sectionId); // Show the requested section if logged in
        return true; // Indicate login check succeeded
    }
}



document.addEventListener('DOMContentLoaded', function() {
    // Get the current booking step from URL or cookies
    const urlParams = new URLSearchParams(window.location.search);
    const bookingId = urlParams.get('booking_id'); // Get booking_id from the URL

    if (bookingId) {
        // Automatically navigate to Step 2 if booking_id exists
        goToStep(2);
    }

    const bookingForm = document.getElementById('booking-form');

    if (bookingForm) {
  // Form submission event listener
document.getElementById('booking-form')?.addEventListener('submit', async function (event) {
    event.preventDefault(); // Prevent the default form submission behavior

    console.log("Form submitted!");  // Debugging line

    // Collect form values
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const phone_number = document.getElementById('phone_number').value;
    const gender = document.getElementById('gender').value;
    const service = document.getElementById('service').value;
    const details = document.getElementById('details').value;

    try {
        // Submit form data to the server
        const response = await fetch('/booking', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getCookie('token')}`, // Use cookie for token
            },
            body: JSON.stringify({
                name,
                email,
                phone_number,
                gender,
                service,
                details,
            }),
        });

        const data = await response.json();

        if (response.ok) {
            const bookingId = data.booking_id; // Assuming the server returns the booking ID
            setCookie('booking_id', bookingId, 15); // Store booking ID in a cookie for 15 minutes
            showNotification(`Thank you ${name} for booking a ${service} service! We will contact you at ${email}.`, 'success');
            
            // Reset the form and move to Step 2 (e.g., for payment)
            bookingForm.reset();
            goToStep(2); // Automatically move to Step 2 after booking is done
        } else {
            throw new Error(data.message);  // Handle server-side errors
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('There was an error with your booking. Please try again.', 'error');
    }
});

       
    }

    // Function to move to a specific step
    function goToStep(stepNumber) {
        const currentStep = document.querySelector('.step.active');
        const nextStep = document.querySelector(`#step-${stepNumber}`);

        if (currentStep) {
            currentStep.classList.add('hidden');
            currentStep.classList.remove('active');
        }

        if (nextStep && nextStep.classList.contains('step')) {
            nextStep.classList.remove('hidden');
            nextStep.classList.add('active');
        } else {
            console.error("Step not found or invalid.");
        }
    }

    // Function to handle the "Next" button click
    function handleNextClick() {
        goToStep(2);
    }

    // Function to handle the "Previous" button click
    function handlePreviousClick() {
        goToStep(1);
    }

    // Attach event listeners to the buttons
    const nextBtn = document.getElementById('nextBtn');
    const prevBtn = document.getElementById('prevBtn');

    if (nextBtn) {
        nextBtn.addEventListener('click', handleNextClick);
    } else {
        console.error('Next button not found.');
    }

    if (prevBtn) {
        prevBtn.addEventListener('click', handlePreviousClick);
    } else {
        console.error('Previous button not found.');
    }
});

// Handle form submission for enquiries
document.getElementById('enquiries-form')?.addEventListener('submit', async function (event) {
    event.preventDefault();

    const token = getCookie('token'); // Use utility function to get the token
    if (!token) {
        showNotification('You must be logged in to make an enquiry.', 'error');
        showSection('login'); // Show the login section
        return;
    }

    const name = document.getElementById('enquiry-name').value;
    const email = document.getElementById('enquiry-email').value;
    const message = document.getElementById('enquiry-message').value;

    try {
        const response = await fetch('/enquiries', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`, // Use cookie for token
            },
            body: JSON.stringify({ name, email, message }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Server Error:', errorText);
            throw new Error(errorText || 'Network response was not ok');
        }

        const result = await response.json();
        showNotification(`Thank you ${name} for your enquiry! We will respond to you at ${email}.`, 'success');
        document.getElementById('enquiries-form').reset();
    } catch (error) {
        console.error('Error:', error);
        showNotification('There was an error with your enquiry. Please try again.', 'error');
    }
});
// Function to dynamically update client list (for demonstration purposes)
const clients = [
    { name: 'Client A', project: 'Web Development' },
    { name: 'Client B', project: 'Mobile Development' },
];

function displayClients() {
    const clientList = document.getElementById('client-list');
    if (clientList) {
        clientList.innerHTML = '';
        clients.forEach(client => {
            const clientDiv = document.createElement('div');
            clientDiv.textContent = `${client.name}: ${client.project}`;
            clientList.appendChild(clientDiv);
        });
    }
}

// Function to show and hide sections
function showSection(sectionId) {
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.classList.add('hidden');
    });

    const sectionToShow = document.getElementById(sectionId);
    if (sectionToShow) {
        sectionToShow.classList.remove('hidden');
    }
}

// Function to shift sections automatically every 5 seconds
function shiftSectionsAutomatically() {
    const links = document.querySelectorAll('header nav ul li a');
    let currentIndex = 0;
    const intervalId = setInterval(() => {
        if (currentIndex >= links.length) {
            currentIndex = 0;
        }
        const sectionId = links[currentIndex].getAttribute('href').substring(1);
        showSection(sectionId);
        currentIndex++;
    }, 5000);

    // Stop shifting when a navigation link is clicked
    document.addEventListener('click', function (event) {
        if (event.target.tagName === 'A') {
            clearInterval(intervalId);
        }
    });
}

// Function to toggle forms based on login status
function toggleForms(isLoggedIn) {
    const bookingSection = document.getElementById('booking');
    const enquiriesSection = document.getElementById('enquiries');
    const loginOptions = document.getElementById('register-link');
    const logoutSection = document.getElementById('logout-link');

    if (bookingSection && enquiriesSection && loginOptions && logoutSection) {
        if (isLoggedIn) {
            bookingSection.classList.remove('hidden');
            enquiriesSection.classList.remove('hidden');
            loginOptions.classList.add('hidden');
            logoutSection.classList.remove('hidden');
        } else {
            bookingSection.classList.add('hidden');
            enquiriesSection.classList.add('hidden');
            loginOptions.classList.remove('hidden');
            logoutSection.classList.add('hidden');
        }
    } else {
        console.error("Some elements are missing in the DOM.");
    }


// Initialize automatic section shifting
shiftSectionsAutomatically();

}
// Function to show notifications
function showNotification(message, type = 'info') {
    const notificationDiv = document.createElement('div');
    notificationDiv.className = `notification ${type}`;
    notificationDiv.textContent = message;

    document.body.appendChild(notificationDiv);

    // Make the notification visible
    setTimeout(() => {
        notificationDiv.classList.add('show');
    }, 100); // Delay to ensure the notification is added to the DOM

    // Remove the notification after 10 seconds
    setTimeout(() => {
        notificationDiv.classList.remove('show');
        notificationDiv.classList.add('hidden');
        // Remove the element from DOM after transition ends
        setTimeout(() => notificationDiv.remove(), 500);
    }, 7000);
}

// Function to show login options
function showLoginOptions(option) {
    const login = document.getElementById('login');
    const register = document.getElementById('register');

    login.classList.add('hidden');
    register.classList.add('hidden');

    if (option === 'login') {
        login.classList.remove('hidden');
    } else if (option === 'register') {
        register.classList.remove('hidden');
    }
}

document.addEventListener('DOMContentLoaded', function () {
    // Attach event listener to the payment method select element
    document.getElementById('payment-method').addEventListener('change', function () {
        const paymentMethod = this.value;
        showPaymentForm(paymentMethod);
    });

    // Show payment info section based on selected payment method
    function showPaymentForm(paymentMethod) {
        const container = document.getElementById('payment-info-container');
        container.innerHTML = ''; // Clear previous content

        let formHtml = '';
        switch (paymentMethod) {
            case 'credit-card':
                formHtml = `
                    <div id="credit-card-info" class="payment-info">
                        <div class="form-group">
                            <label for="card-number">Card Number:</label>
                            <input type="text" id="card-number" name="card-number" placeholder="Enter card number" pattern="\\d{16}" required>
                        </div>
                        <div class="form-group">
                            <label for="card-expiry">Expiry Date:</label>
                            <input type="text" id="card-expiry" name="card-expiry" placeholder="MM/YY" required>
                        </div>
                        <div class="form-group">
                            <label for="card-cvc">CVC:</label>
                            <input type="text" id="card-cvc" name="card-cvc" placeholder="Enter CVC" pattern="\\d{3,4}" required>
                        </div>
                        <button type="button" class="btn-primary" id="submit-credit-card">Submit Credit Card Payment</button>
                    </div>`;
                break;
            case 'paypal':
                formHtml = `
                    <div id="paypal-info" class="payment-info">
                        <div class="form-group">
                            <label for="payment-email">PayPal Email:</label>
                            <input type="email" id="payment-email" name="payment-email" placeholder="Enter PayPal email" required>
                        </div>
                        <div class="form-group">
                            <label for="transaction-id">Transaction ID:</label>
                            <input type="text" id="transaction-id" name="transaction-id" placeholder="Enter transaction ID" required>
                        </div>
                        <button type="button" class="btn-primary" id="submit-paypal">Submit PayPal Payment</button>
                    </div>`;
                break;
            case 'bank-transfer':
                formHtml = `
                    <div id="bank-transfer-info" class="payment-info">
                        <div class="form-group">
                            <label for="bank-name">Bank Name:</label>
                            <input type="text" id="bank-name" name="bank-name" placeholder="Enter bank name" required>
                        </div>
                        <div class="form-group">
                            <label for="account-number">Account Number:</label>
                            <input type="text" id="account-number" name="account-number" placeholder="Enter account number" required>
                        </div>
                        <div class="form-group">
                            <label for="transactions-code">Transaction Code:</label>
                            <input type="text" id="transactions-code" name="transactions-code" placeholder="Enter transaction code" required>
                        </div>
                        <div class="form-group">
                            <label for="phone-number">Phone Number:</label>
                            <input type="text" id="phone-number" name="phone-number" placeholder="Enter phone number" required>
                        </div>
                        <button type="button" class="btn-primary" id="submit-bank-transfer">Submit Bank Transfer Payment</button>
                    </div>`;
                break;
            case 'mpesa':
                formHtml = `
                    <div id="mpesa-info" class="payment-info">
                        <div class="form-group">
                            <label for="mpesa-number">Mpesa Number:</label>
                            <input type="tel" id="mpesa-number" name="mpesa-number" placeholder="Enter Mpesa number" pattern="\\d{10}" required>
                        </div>
                        <div class="form-group">
                            <label for="transaction-code">Transaction Code:</label>
                            <input type="text" id="transaction-code" name="transaction-code" placeholder="Enter transaction code" required>
                        </div>
                        <button type="button" class="btn-primary" id="submit-mpesa">Submit Mpesa Payment</button>
                    </div>`;
                break;
            default:
                console.error('Invalid payment method selected');
                return;
        }
        container.innerHTML = formHtml;

        // Attach event listeners to buttons
        document.getElementById('submit-credit-card')?.addEventListener('click', submitPayment);
        document.getElementById('submit-paypal')?.addEventListener('click', submitPayment);
        document.getElementById('submit-bank-transfer')?.addEventListener('click', submitPayment);
        document.getElementById('submit-mpesa')?.addEventListener('click', submitPayment);
    }

    // Function to handle payment submission
    async function submitPayment() {
        const paymentMethod = document.getElementById('payment-method').value;

        // Show loader
        showLoader();

        try {
            switch (paymentMethod) {
                case 'credit-card':
                    const cardNumber = document.getElementById('card-number').value;
                    const cardExpiry = document.getElementById('card-expiry').value;
                    const cardCvc = document.getElementById('card-cvc').value;
                    if (!cardNumber || !cardExpiry || !cardCvc) {
                        showNotification('Please provide all required credit card details.','error');
                        return;
                    }
                    await saveCreditCardPayment({ cardNumber, cardExpiry, cardCvc });
                    break;

                case 'paypal':
                    const paymentEmail = document.getElementById('payment-email').value;
                    const transactionId = document.getElementById('transaction-id').value;
                    if (!paymentEmail || !transactionId) {
                        showNotification('Please provide all required PayPal details.','error');
                        return;
                    }
                    await savePayPalPayment({ paymentEmail, transactionId });
                    break;

                case 'bank-transfer':
                    const bankName = document.getElementById('bank-name').value;
                    const accountNumber = document.getElementById('account-number').value;
                    const transactionsCode = document.getElementById('transactions-code').value;
                    const phoneNumber = document.getElementById('phone-number').value;
                    if (!bankName || !accountNumber || !transactionsCode || !phoneNumber) {
                        showNotification('Please provide all required bank transfer details.','error');
                        return;
                    }
                    await saveBankTransferDetails({ bankName, accountNumber, phoneNumber, transactionsCode });
                    break;

                case 'mpesa':
                    const mpesaNumber = document.getElementById('mpesa-number').value;
                    const mpesaTransactionCode = document.getElementById('transaction-code').value;
                    if (!mpesaNumber || !mpesaTransactionCode) {
                        showNotification('Please provide all required Mpesa details.','error');
                        return;
                    }
                    await saveMpesaPayment({ mpesaNumber, mpesaTransactionCode });
                    break;

                default:
                    showNotification('Invalid payment method selected.','error');
                    break;
            }
        } catch (error) {
            console.error('Payment processing error:', error);
            showNotification('An error occurred while processing your payment.','error');
        } finally {
            // Hide loader
            hideLoader();
        }
    }

    // Helper functions to show and hide loader
    function showLoader() {
        const loader = document.getElementById('loader');
        if (loader) {
            loader.classList.remove('hidden');
        }
    }

    function hideLoader() {
        const loader = document.getElementById('loader');
        if (loader) {
            loader.classList.add('hidden');
        }
    }

  // Utility function to get cookies
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Save payment credit card
async function saveCreditCardPayment(details) {
    const bookingId = getCookie('booking_id');  // Retrieve booking_id from cookies
    const token = getCookie('token');  // Retrieve token from cookies

    if (!bookingId) {
        showNotification('No booking ID found.', 'error');
        return;
    }

    try {
        const response = await fetch('/credit-card-payments', {
            method: 'POST',
            headers: getHeaders(),  // Use the headers function
            body: JSON.stringify({
                booking_id: bookingId,  // Include booking_id in the request body
                card_number: details.cardNumber,
                expiry_date: details.cardExpiry,
                cvc: details.cardCvc
            }),
        });

        const result = await response.json();
        if (response.ok) {
            showNotification('Credit Card payment processed successfully.', 'success');
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('There was an error processing your payment. Please try again.', 'error');
    }
}

// Save payment PayPal
async function savePayPalPayment(details) {
    const bookingId = getCookie('booking_id');  // Retrieve booking_id from cookies
    const token = getCookie('token');  // Retrieve token from cookies

    if (!bookingId) {
        showNotification('No booking ID found.', 'error');
        return;
    }

    try {
        const response = await fetch('/paypal-payments', {
            method: 'POST',
            headers: getHeaders(),  // Use the headers function
            body: JSON.stringify({
                booking_id: bookingId,  // Include booking_id in the request body
                payment_email: details.paymentEmail,
                transaction_id: details.transactionId
            }),
        });

        const result = await response.json();
        if (response.ok) {
            showNotification('PayPal payment processed successfully.', 'success');
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('There was an error processing your PayPal payment. Please try again.', 'error');
    }
}

// Save payment bank transfer
async function saveBankTransferDetails(details) {
    const bookingId = getCookie('booking_id');  // Retrieve booking_id from cookies
    const token = getCookie('token');  // Retrieve token from cookies

    if (!bookingId) {
        showNotification('No booking ID found.', 'error');
        return;
    }

    try {
        const response = await fetch('/bank-transfer-payments', {
            method: 'POST',
            headers: getHeaders(),  // Use the headers function
            body: JSON.stringify({
                booking_id: bookingId,  // Include booking_id in the request body
                bank_name: details.bankName,
                account_number: details.accountNumber,
                transactions_code: details.transactionsCode,
                phone_number: details.phoneNumber
            }),
        });

        const result = await response.json();
        if (response.ok) {
            showNotification('Bank Transfer payment processed successfully.', 'success');
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('There was an error processing your Bank Transfer payment. Please try again.', 'error');
    }
}

// Save payment Mpesa
async function saveMpesaPayment(details) {
    const bookingId = getCookie('booking_id');  // Retrieve booking_id from cookies
    const token = getCookie('token');  // Retrieve token from cookies

    if (!bookingId) {
        showNotification('No booking ID found.', 'error');
        return;
    }

    try {
        const response = await fetch('/mpesa-payments', {
            method: 'POST',
            headers: getHeaders(),  // Use the headers function
            body: JSON.stringify({
                booking_id: bookingId,  // Include booking_id in the request body
                mpesa_number: details.mpesaNumber,
                transaction_code: details.mpesaTransactionCode
            }),
        });

        const result = await response.json();
        if (response.ok) {
            showNotification('Mpesa payment processed successfully.', 'success');
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('There was an error processing your Mpesa payment. Please try again.', 'error');
    }
}

// Get headers with Authorization if needed
function getHeaders() {
    const token = getCookie('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`  // Retrieve token from cookies
    };
}
});