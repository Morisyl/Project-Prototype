document.addEventListener('DOMContentLoaded', function () {
    displayClients();
    showSection('home'); // Show the home section by default on page load
    shiftSectionsAutomatically(); // Start shifting through sections automatically

    // Check if the user is logged in
    const isLoggedIn = localStorage.getItem('loggedIn') === 'true';
    toggleForms(isLoggedIn);

    // Event listener for login form submission
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
                localStorage.setItem('loggedIn', 'true');
                showNotification('Login successful!', 'success');
                showSection('home');
                toggleForms(true);
            } else {
                showNotification('Invalid username or password. Please try again.', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            showNotification('There was an error with your login. Please try again.', 'error');
        }
    });

    // Event listener for logout
    document.getElementById('logout-btn')?.addEventListener('click', function () {
        localStorage.setItem('loggedIn', 'false');
        showNotification('Logged out successfully!', 'success');
        showSection('home');
        toggleForms(false);
    });

    // Event listener for forgot password form submission
    document.getElementById('forgot-password-form')?.addEventListener('submit', async function (event) {
        event.preventDefault();
        const email = document.getElementById('forgot-email').value;

        try {
            const response = await fetch('/forgot-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email }),
            });
            await response.json();
            showNotification(`Password reset link has been sent to ${email}`, 'success');
            showLoginOptions('login'); // Return to login after password reset
        } catch (error) {
            console.error('Error:', error);
            showNotification('There was an error sending the password reset. Please try again.', 'error');
        }
    });

    // Event listener for register form submission
    document.getElementById('register-form')?.addEventListener('submit', async function (event) {
        event.preventDefault();
        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;
        const email = document.getElementById('register-email').value;

        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    password,
                    email,
                }),
            });
            const data = await response.json();
            showNotification(`Registration successful for ${username}. Welcome!`, 'success');
            showLoginOptions('login'); // Return to login after registration
        } catch (error) {
            console.error('Error:', error);
            showNotification('There was an error with your registration. Please try again.', 'error');
        }
    });

    // Event listeners for login options
    document.getElementById('forgot-password-link')?.addEventListener('click', function (event) {
        event.preventDefault();
        showLoginOptions('forgot-password');
    });

    document.getElementById('register-link')?.addEventListener('click', function (event) {
        event.preventDefault();
        showLoginOptions('register');
    });

    document.getElementById('login-link')?.addEventListener('click', function (event) {
        event.preventDefault();
        showLoginOptions('login');
    });

    // Initial section to show
    showSection(localStorage.getItem('loggedIn') === 'true' ? 'home' : 'login');
});

// Function to check login status before showing section
function checkLogin(sectionId) {
    if (localStorage.getItem('loggedIn') !== 'true') {
        showNotification('You must be logged in to access this section.', 'error');
        showSection('login'); // Show the login section
    } else {
        showSection(sectionId);
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
            },
            body: JSON.stringify({
                name,
                email,
                message,
            }),
        });
        const data = await response.text();
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

// Function to toggle visibility of forms based on login status
function toggleForms(isLoggedIn) {
    const bookingSection = document.getElementById('booking');
    const enquiriesSection = document.getElementById('enquiries');
    const loginOptions = document.getElementById('login');

    if (isLoggedIn) {
        bookingSection.classList.remove('hidden');
        enquiriesSection.classList.remove('hidden');
        loginOptions.classList.add('hidden');
        document.getElementById('logout-btn')?.classList.remove('hidden');
    } else {
        bookingSection.classList.add('hidden');
        enquiriesSection.classList.add('hidden');
        loginOptions.classList.remove('hidden');
        document.getElementById('logout-btn')?.classList.add('hidden');
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
