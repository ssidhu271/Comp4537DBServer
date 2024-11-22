//CHATGPT assisted with this code

const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

const validateNumber = (number) => {
    return !isNaN(number) && isFinite(number);
};

module.exports = { validateEmail, validateNumber };
