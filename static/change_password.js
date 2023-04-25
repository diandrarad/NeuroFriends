function checkPassword() {
    const registerBtn = document.getElementById("register-btn");
    var password = document.getElementsByName("password")[0].value;
    var lowercaseRegex = /[a-z]/;
    var uppercaseRegex = /[A-Z]/;
    var numberRegex = /[0-9]/;
    var specialRegex = /[!@#$%^&*(),.?\":{}|<>]/;
    var lengthOk = password.length >= 8;
    var lowercaseOk = lowercaseRegex.test(password);
    var uppercaseOk = uppercaseRegex.test(password);
    var numberOk = numberRegex.test(password);
    var specialOk = specialRegex.test(password);
    var passwordOk = lengthOk && lowercaseOk && uppercaseOk && numberOk && specialOk;
    var passwordHelpBlock = document.getElementById("passwordHelpBlock");
    if (!passwordOk) {
        passwordHelpBlock.classList.add("text-danger");
        passwordHelpBlock.classList.remove("text-success");
    } else {
        passwordHelpBlock.classList.add("text-success");
        passwordHelpBlock.classList.remove("text-danger");
        registerBtn.disabled = false;
    }
}