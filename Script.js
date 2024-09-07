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


// Function to handle booking form submission

document.addEventListener('DOMContentLoaded', function() {
    const bookingForm = document.getElementById('booking-form');

    if (bookingForm) {
        bookingForm.addEventListener('submit', async function (event) {
            event.preventDefault(); // Prevent the default form submission behavior

            console.log("Form submitted!");  // Debugging line

            // Collect form values
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const gender = document.getElementById('gender').value;
            const homePhone = document.getElementById('home-phone').value;
            const officePhone = document.getElementById('office-phone').value;
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
                        gender,
                        homePhone,
                        officePhone,
                        service,
                        details,
                    }),
                });

                const data = await response.text();

                if (response.ok) {
                    showNotification(`Thank you ${name} for booking a ${service} service! We will contact you at ${email}.`, 'success');
                    bookingForm.reset(); // Reset the form
                } else {
                    throw new Error(data);  // Handle server-side errors
                }
            } catch (error) {
                console.error('Error:', error);
                showNotification('There was an error with your booking. Please try again.', 'error');
            }
        });
    }
});


document.addEventListener("DOMContentLoaded", function() {
    function goToStep(stepNumber) {
        const steps = document.querySelectorAll('.step');
        steps.forEach(step => {
            step.classList.add('hidden');
            step.classList.remove('active');
        });

        const targetStep = document.getElementById(`step-${stepNumber}`);
        if (targetStep) {
            targetStep.classList.remove('hidden');
            targetStep.classList.add('active');
        } else {
            console.error(`Step ${stepNumber} not found.`);
        }
    }

    // Event listener for the 'Next' button
    document.getElementById('nextBtn').addEventListener('click', function() {
        goToStep(2); // Go to Step 2
    });

    // Event listener for the 'Previous' button
    document.getElementById('prevBtn').addEventListener('click', function() {
        goToStep(1); // Go back to Step 1
    });

    // Optional: Handle form submission if necessary
    document.getElementById('submit.booking-form').addEventListener('submit', async function(event) {
        event.preventDefault(); // Prevent the default form submission behavior

        // Collect form values and handle submission as needed
        console.log("Form submitted!"); // Replace with your form submission logic
    });
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

    try {
        const response = await fetch('/enquiries', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: JSON.stringify({ name, email, message }),
        });
        await response.text();
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
        var paymentMethod = this.value;
        showPaymentInfo(paymentMethod);
    });
});

function showPaymentInfo(paymentMethod) {
    // Hide all payment info sections
    var paymentInfos = document.querySelectorAll('.payment-info');
    paymentInfos.forEach(function (el) {
        el.style.display = 'none';
    });

    // Show the selected payment info section
    var selectedPaymentInfo = document.getElementById(paymentMethod + '-info');
    if (selectedPaymentInfo) {
        selectedPaymentInfo.style.display = 'block';
    }
}
    var creditCardInfo = document.getElementById("credit-card-info");
    var paypalInfo = document.getElementById("paypal-info");
    var bankTransferInfo = document.getElementById("bank-transfer-info");
    var mpesaInfo = document.getElementById("mpesa-info");
    // Hide all payment info sections
    creditCardInfo.classList.add("hidden");
    paypalInfo.classList.add("hidden");
    bankTransferInfo.classList.add("hidden");
    mpesaInfo.classList.add("hidden");

    // Show the relevant payment info section
    switch (paymentMethod) {
        case "credit-card":
            creditCardInfo.classList.remove("hidden");
            console.log("Showing Credit Card Info");
            break;
        case "paypal":
            paypalInfo.classList.remove("hidden");
            console.log("Showing PayPal Info");
            break;
        case "bank-transfer":
            bankTransferInfo.classList.remove("hidden");
            console.log("Showing Bank Transfer Info");
            break;
        case "mpesa":
            mpesaInfo.classList.remove("hidden");
            console.log("Showing Mpesa Info");
            break;
        default:
            console.error("Invalid payment method selected");
    }


// Function to retrieve user details
async function getUserDetails(username) {
    try {
        const response = await fetch(`/api/get-user/${username}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        if (response.ok) {
            return { userId: data.userId };
        } else {
            console.error('Error fetching user details:', data.message);
            return { userId: null };
        }
    } catch (error) {
        console.error('Error fetching user details:', error);
        return { userId: null };
    }
}

// Function to retrieve booking details
async function getBookingDetails(userId) {
    try {
        const response = await fetch(`/api/get-booking-details/${userId}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        if (response.ok) {
            return {
                bookingId: data.bookingId,
                paymentAmount: data.paymentAmount
            };
        } else {
            console.error('Error fetching booking details:', data.message);
            return { bookingId: null, paymentAmount: null };
        }
    } catch (error) {
        console.error('Error fetching booking details:', error);
        return { bookingId: null, paymentAmount: null };
    }
}

async function submitPayment() {}
    // Retrieve the payment method and username
    const paymentMethod = document.querySelector('input[name="payment-method"]:checked').value;
    const username = document.getElementById('username').value; // Retrieve username input

    async function getUserDetails(username) {
        try {
            const response = await fetch(`/api/get-user/${username}`);
            const data = await response.json();
            return data; // Return raw data for simplicity
        } catch (error) {
            console.error('Error:', error);
            return null; // Return null if there's an error
        }
    }
    
    // Handle payment based on selected method
async function submitPayment() {
    // Get the selected payment method
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
                const payment_email = document.getElementById('payment-email').value
                const transaction_id = document.getElementById('transaction-id').value
                if ( !payment_email || !transaction_id  ) {
                    alert('Please provide all required paypal payment details.');
                    return;
                }

                await savePayPalPayment({ payment_id, payment_email, transaction_id });
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
                const transactionCode = document.getElementById('transaction-code').value;
                if (!mpesaNumber || !transactionCode) {
                    alert('Please provide all required Mpesa details.');
                    return;
                }
                await saveMpesaPayment({ mpesaNumber, transactionCode });
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

// Helper function to get headers with token
function getHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
    };
}

// Show and hide loader
function showLoader() {
    document.getElementById('loader').classList.remove('hidden');
}

function hideLoader() {
    document.getElementById('loader').classList.add('hidden');
}

// Save payment methods (example functions, need to be implemented)
async function saveCreditCardPayment(details) {
    const response = await fetch('/api/credit-card-payments', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(details),
    });
    const result = await response.json();
    if (response.ok) {
        alert('Credit Card payment processed successfully.');
    } else {
        alert(`Error: ${result.message}`);
    }
}

async function savePayPalPayment() {
    const response = await fetch('/api/paypal-payments', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({}),
    });
    const result = await response.json();
    if (response.ok) {
        alert('PayPal payment processed successfully.');
    } else {
        alert(`Error: ${result.message}`);
    }
}

async function saveBankTransferDetails(details) {
    const response = await fetch('/api/bank-transfer-details', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(details),
    });
    const result = await response.json();
    if (response.ok) {
        alert('Bank Transfer payment processed successfully.');
    } else {
        alert(`Error: ${result.message}`);
    }
}

async function saveMpesaPayment(details) {
    const response = await fetch('/api/mpesa-payments', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(details),
    });
    const result = await response.json();
    if (response.ok) {
        alert('Mpesa payment processed successfully.');
    } else {
        alert(`Error: ${result.message}`);
    }
}


// Helper function to get headers with token
function getHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
    };
}


// Show and hide loader
function showLoader() {
    document.getElementById('loader').classList.remove('hidden');
}

function hideLoader() {
    document.getElementById('loader').classList.add('hidden');
}



