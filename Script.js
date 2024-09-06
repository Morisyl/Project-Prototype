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
    
  
// Function to show/hide sections
function showSection(sectionId) {
    // Logic to show or hide sections as needed
    console.log("Showing section: " + sectionId);
}

// Function to check if user is logged in before showing certain sections
function checkLogin(sectionId) {
    if (localStorage.getItem('userLoggedIn')) {
        showSection(sectionId);
    } else {
        alert("You need to log in to access this section.");
        showSection('register');
    }
}

// Function to log out the user
function logoutUser() {
    localStorage.removeItem('userLoggedIn');
    localStorage.removeItem('token'); // Remove token if stored for auth purposes

    // Hide the logout link and show the register link
    document.getElementById('logout-link').classList.add('hidden');
    document.getElementById('register-link').classList.remove('hidden');

    alert("You have been logged out.");
    window.location.href = '#home';  // Optional: Redirect to home page
}

// Simulate login
function userLoggedIn() {
    // Store login status
    localStorage.setItem('userLoggedIn', 'true');

    // Hide register link and show the logout link
    document.getElementById('register-link').classList.add('hidden');
    document.getElementById('logout-link').classList.remove('hidden');
}

document.addEventListener("DOMContentLoaded", function() {
    // Check if user is logged in
    if (localStorage.getItem('userLoggedIn')) {
        userLoggedIn(); // If logged in, update the UI accordingly
    }
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

// Function to handle form steps in booking
function nextStep() {
    const currentStep = document.querySelector('.step.active');
    const nextStep = currentStep.nextElementSibling;
    if (nextStep) {
        currentStep.classList.add('hidden');
        nextStep.classList.remove('hidden');
        nextStep.classList.add('active');
    }
}

function previousStep() {
    const currentStep = document.querySelector('.step.active');
    const previousStep = currentStep.previousElementSibling;
    if (previousStep) {
        currentStep.classList.add('hidden');
        previousStep.classList.remove('hidden');
        previousStep.classList.add('active');
    }
}
// Function to handle booking form submission
document.getElementById('booking-form')?.addEventListener('submit', async function (event) {
    event.preventDefault();

    if (localStorage.getItem('loggedIn') !== 'true') {
        showNotification('You must be logged in to make a booking.', 'error');
        showSection('login'); // Show the login section
        return;
    }

    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const gender = document.querySelector('input[name="gender"]:checked').value;
    const homePhone = document.getElementById('home-phone').value;
    const officePhone = document.getElementById('office-phone').value;
    const service = document.getElementById('service').value;
    const details = document.getElementById('details').value;

    try {
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
        showNotification(`Thank you ${name} for booking a ${service} service! We will contact you at ${email}.`, 'success');
        document.getElementById('booking-form').reset();
    } catch (error) {
        console.error('Error:', error);
        showNotification('There was an error with your booking. Please try again.', 'error');
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

/// Function to toggle visibility of forms based on login status
function toggleForms(isLoggedIn) {
    const bookingSection = document.getElementById('booking');
    const enquiriesSection = document.getElementById('enquiries');
    const loginOptions = document.getElementById('register-link'); // Changed to the correct element
    const logoutSection = document.getElementById('logout-link');  // Changed to the correct element

    // Ensure the elements are selected correctly
    if (bookingSection && enquiriesSection && loginOptions && logoutSection) {
        if (isLoggedIn) {
            bookingSection.classList.remove('hidden');
            enquiriesSection.classList.remove('hidden');
            loginOptions.classList.add('hidden');  // Hide the login option
            logoutSection.classList.remove('hidden');  // Show the logout option
        } else {
            bookingSection.classList.add('hidden');
            enquiriesSection.classList.add('hidden');
            loginOptions.classList.remove('hidden');  // Show the login option
            logoutSection.classList.add('hidden');  // Hide the logout option
        }
    } else {
        console.error("Some elements are missing in the DOM.");
    }
}

// Simulate checking the login status on page load
document.addEventListener("DOMContentLoaded", function() {
    const isLoggedIn = localStorage.getItem('userLoggedIn') === 'true';
    toggleForms(isLoggedIn);  // Call toggleForms based on the login status
});

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

    // Remove the notification after 3 seconds
    setTimeout(() => {
        notificationDiv.classList.remove('show');
        notificationDiv.classList.add('hidden');
        // Remove the element from DOM after transition ends
        setTimeout(() => notificationDiv.remove(), 300);
    }, 3000);
}

// Function to show login options
function showLoginOptions(option) {
    const login = document.getElementById('login');
    const forgotPassword = document.getElementById('forgot-password');
    const register = document.getElementById('register');

    login.classList.add('hidden');
    forgotPassword.classList.add('hidden');
    register.classList.add('hidden');

    if (option === 'login') {
        login.classList.remove('hidden');
    } else if (option === 'forgot-password') {
        forgotPassword.classList.remove('hidden');
    } else if (option === 'register') {
        register.classList.remove('hidden');
    }
}

// Function to show payment info based on selected payment method
function showPaymentInfo() {
    var paymentMethod = document.getElementById("payment-method").value;
    var creditCardInfo = document.getElementById("credit-card-info");
    var paypalInfo = document.getElementById("paypal-info");
    var bankTransferInfo = document.getElementById("bank-transfer-info");

    creditCardInfo.classList.add("hidden");
    paypalInfo.classList.add("hidden");
    bankTransferInfo.classList.add("hidden");

    if (paymentMethod === "credit-card") {
        creditCardInfo.classList.remove("hidden");
    } else if (paymentMethod === "paypal") {
        paypalInfo.classList.remove("hidden");
    } else if (paymentMethod === "bank-transfer") {
        bankTransferInfo.classList.remove("hidden");
    }
}

// Handle payment
async function makePayment(bookingId, paymentMethod, paymentStatus, paymentAmount) {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Please log in first');
        return;
    }

    try {
        const response = await fetch('/payments', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ bookingId, paymentMethod, paymentStatus, paymentAmount }),
        });

        const data = await response.json();
        if (response.ok) {
            alert('Payment processed successfully');
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (error) {
        console.error('Error processing payment:', error);
    }
}

// Handle credit card payment
async function saveCreditCardPayment(paymentId, cardNumber, expiryDate, cvc) {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Please log in first');
        return;
    }

    try {
        const response = await fetch('/credit-card-payments', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ paymentId, cardNumber, expiryDate, cvc }),
        });

        const data = await response.json();
        if (response.ok) {
            alert('Credit card payment saved successfully');
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (error) {
        console.error('Error saving credit card payment:', error);
    }
}

// Handle bank transfer details
async function saveBankTransferDetails(paymentId, bankName, accountNumber, sortCode) {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Please log in first');
        return;
    }

    try {
        const response = await fetch('/bank-transfer-details', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ paymentId, bankName, accountNumber, sortCode }),
        });

        const data = await response.json();
        if (response.ok) {
            alert('Bank transfer details saved successfully');
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (error) {
        console.error('Error saving bank transfer details:', error);
    }
}

// Handle PayPal payment
async function savePayPalPayment(paymentId, transactionId, paypalStatus) {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Please log in first');
        return;
    }

    try {
        const response = await fetch('/paypal-payments', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ paymentId, transactionId, paypalStatus }),
        });

        const data = await response.json();
        if (response.ok) {
            alert('PayPal payment saved successfully');
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (error) {
        console.error('Error saving PayPal payment:', error);
    }
}
