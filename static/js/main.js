window.onload = function () {
	document.getElementById("password").onchange = validatePassword;
	document.getElementById("password_confirm").onchange = validatePassword;
}
function validatePassword(){
var pass2=document.getElementById("password").value;
var pass1=document.getElementById("password_confirm").value;
if(pass1!=pass2)
	document.getElementById("password_confirm").setCustomValidity("Passwords Don't Match");
else
	document.getElementById("password_confirm").setCustomValidity('');	 
//empty string means no validation error
}

document.getElementById("uploadBtn").onchange = function () {
    document.getElementById("uploadFile").value = this.value;
};
