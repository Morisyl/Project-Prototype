document.addEventListener('DOMContentLoaded', function () {
    displayClients();
    showSection('home'); // Show the home section by default on page load
    shiftSectionsAutomatically(); // Start shifting through sections automatically

    // Check if the user is logged in
    const isLoggedIn = localStorage.getItem('loggedIn') === 'true';
    toggleForms(isLoggedIn);

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
                body: JSON.stringify({ email, password }),
            });
    
            const data = await response.json();
    
            if (data.token) {
                // Store token and login status
                localStorage.setItem('token', data.token);
                localStorage.setItem('loggedIn', 'true');
    
                // Update UI
                showNotification('Login successful!', 'success');
                toggleForms(true);
    
                // Redirect to the home section
                window.location.hash = '#home';
                showSection('home');  // Ensure the home section is visible
            } else {
                showNotification('Invalid username or password. Please try again.', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            showNotification('There was an error with your login. Please try again.', 'error');
        }
    });
    
  
/// Function to show a section based on ID
function showSection(sectionId) {
    console.log("Showing section: " + sectionId);
    // Logic to show/hide sections based on sectionId
    const sections = document.querySelectorAll('.section'); // Assuming all sections have a class of 'section'
    sections.forEach(section => {
        if (section.id === sectionId) {
            section.classList.remove('hidden');
        } else {
            section.classList.add('hidden');
        }
    });
}

// Function to check if user is logged in before showing certain sections
function checkLogin(sectionId) {
    const token = localStorage.getItem('token');
    if (token && isValidToken(token)) {
        showSection(sectionId);
    } else {
        alert("You need to log in to access this section.");
        showSection('register');
    }
}

// Event listener for the logout link click event
document.getElementById('logout-link')?.addEventListener('click', async function (event) {
    event.preventDefault(); // Prevent default anchor behavior

    // Call the logout function when the user clicks the logout link
    await logoutUser();
});

function userLoggedIn(token) {
    localStorage.setItem('userLoggedIn', 'true');
    localStorage.setItem('token', token);  // Store JWT or token
    document.getElementById('register-link').classList.add('hidden');
    document.getElementById('logout-link').classList.remove('hidden');
    showSection('home'); // Show home section
}

async function logoutUser() {
    const token = localStorage.getItem('token'); // Retrieve the token from localStorage

    try {
        // Make an API call to log out (blacklist token on the server-side)
        await fetch('/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        // If successful, clear localStorage and update UI
        localStorage.removeItem('userLoggedIn');
        localStorage.removeItem('token');
        alert("You have been logged out.");

        // Update the UI to reflect the logged-out state
        document.getElementById('logout-link').classList.add('hidden');
        document.getElementById('register-link').classList.remove('hidden');

        // Redirect to the home section
        showSection('home');
    } catch (error) {
        console.error('Error during logout:', error);
        alert("There was an issue logging out. Please try again.");
    }
}

// Check for user login status on page load
document.addEventListener("DOMContentLoaded", function() {
    if (localStorage.getItem('userLoggedIn') && localStorage.getItem('token')) {
        // If the user is logged in, make sure to reflect that in the UI
        userLoggedIn(localStorage.getItem('token'));
    } else {
        // If the user is not logged in, show the registration section
        showSection('register');
    }
});

// Simulate checking the login status on page load
document.addEventListener("DOMContentLoaded", function() {
    const isLoggedIn = localStorage.getItem('userLoggedIn') === 'true';
    toggleForms(isLoggedIn);  // Call toggleForms based on the login status
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
});
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
    showSection(localStorage.getItem('loggedIn') === 'true' ? 'home' : 'logout');
});

// Function to check login status before showing section
function checkLogin(sectionId) {
    if (localStorage.getItem('loggedIn') !== 'true') {
        showNotification('You must be logged in to access this section.', 'error');
        showSection('register'); // Show the register section
    } else {
        showSection(sectionId);
    }
}

//Function to handle booking form submission
document.addEventListener('DOMContentLoaded', function() {
    // Get the current booking step from URL or localStorage
    const urlParams = new URLSearchParams(window.location.search);
    const bookingId = urlParams.get('booking_id'); // Get booking_id from the URL

    if (bookingId) {
        // Automatically navigate to Step 2 if booking_id exists
        goToStep(2);
    }

    const bookingForm = document.getElementById('booking-form');

    if (bookingForm) {
        bookingForm.addEventListener('submit', async function (event) {
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
                // Submit form data
                const response = await fetch('/booking', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('token')}`,
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
                    localStorage.setItem('booking_id', bookingId); // Store booking ID in localStorage
                    showNotification(`Thank you ${name} for booking a ${service} service! We will contact you at ${email}.`, 'success');
                    
                    bookingForm.reset(); // Reset the form
                    // window.location.href = `/payments?booking_id=${bookingId}`; // Redirect to payments page with booking ID
                } else {
                    throw new Error(data.message);  // Handle server-side errors
                }
            } catch (error) {
                console.error('Error:', error);
                showNotification('There was an error with your booking. Please try again.', 'error');
            }
        });
    }
});


document.addEventListener("DOMContentLoaded", function () {
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


// Function to handle enquiry form submission
document.getElementById('enquiries-form')?.addEventListener('submit', async function (event) {
    event.preventDefault();

    if (localStorage.getItem('loggedIn') !== 'true') {
        showNotification('You must be logged in to make an enquiry.', 'error');
        showSection('login'); // Show the login section
        return;
    }
    const name = document.getElementById('enquiry-name').value;
    const email = document.getElementById('enquiry-email').value;
    const message = document.getElementById('enquiry-message').value;

    console.log('Submitting enquiry:', { name, email, message });

    try {
        const response = await fetch('/enquiries', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: JSON.stringify({ name, email, message }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Server Error:', errorText);
            throw new Error('Network response was not ok');
        }

        const result = await response.json();
        console.log('Server response:', result);

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
                        alert('Please provide all required credit card details.');
                        return;
                    }
                    await saveCreditCardPayment({ cardNumber, cardExpiry, cardCvc });
                    break;

                case 'paypal':
                    const paymentEmail = document.getElementById('payment-email').value;
                    const transactionId = document.getElementById('transaction-id').value;
                    if (!paymentEmail || !transactionId) {
                        alert('Please provide all required PayPal details.');
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
                        alert('Please provide all required bank transfer details.');
                        return;
                    }
                    await saveBankTransferDetails({ bankName, accountNumber, phoneNumber, transactionsCode });
                    break;

                case 'mpesa':
                    const mpesaNumber = document.getElementById('mpesa-number').value;
                    const mpesaTransactionCode = document.getElementById('transaction-code').value;
                    if (!mpesaNumber || !mpesaTransactionCode) {
                        alert('Please provide all required Mpesa details.');
                        return;
                    }
                    await saveMpesaPayment({ mpesaNumber, mpesaTransactionCode });
                    break;

                default:
                    alert('Invalid payment method selected.');
                    break;
            }
        } catch (error) {
            console.error('Payment processing error:', error);
            alert('An error occurred while processing your payment.');
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

    // Save payment credit card
    async function saveCreditCardPayment(details) {
        const response = await fetch('/credit-card-payments', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({
                booking_id: details.bookingId,
                card_number: details.cardNumber,
                expiry_date: details.cardExpiry,
                cvc: details.cardCvc
            }),
        });
        const result = await response.json();
        if (response.ok) {
            alert('Credit Card payment processed successfully.');
        } else {
            alert(`Error: ${result.message}`);
        }
    }
    
// Save payment Paypal
    async function savePayPalPayment(details) {
        const response = await fetch('/paypal-payments', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({
                booking_id: details.bookingId,
                payment_email: details.paymentEmail,
                transaction_id: details.transactionId
            }),   
        });
        const result = await response.json();
        if (response.ok) {
            alert('PayPal payment processed successfully.');
        } else {
            alert(`Error: ${result.message}`);
        }
    }
// Save payment bank transfer
    async function saveBankTransferDetails(details) {
        const response = await fetch('/bank-transfer-payments', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({
                booking_id: details.bookingId,
                bank_name: details.bankName,
                account_number: details.accountNumber,
                transactions_code: details.transactionsCode,
                phone_number: details.phoneNumber
            }),
        });
        const result = await response.json();
        if (response.ok) {
            alert('Bank Transfer payment processed successfully.');
        } else {
            alert(`Error: ${result.message}`);
        }
    }
    
// Save payment mpesa
    async function saveMpesaPayment(details) {
        const response = await fetch('/mpesa-payments', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({
                booking_id: details.bookingId,
                mpesa_number: details.mpesaNumber,
                transaction_code: details.mpesaTransactionCode
            }),
        });
        const result = await response.json();
        if (response.ok) {
            alert('Mpesa payment processed successfully.');
        } else {
            alert(`Error: ${result.message}`);
        }
    }
    

    // Get headers with Authorization if needed
    function getHeaders() {
        return {
            'Content-Type': 'application/json',
            // 'Authorization': 'Bearer ' + localStorage.getItem('token') // Example
        };
    }
});
