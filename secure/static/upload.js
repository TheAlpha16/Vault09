const dialog = document.getElementById("dialog");
const blurme = document.getElementById("blurme");
const inputElement = document.querySelector(".drop-zone__input");
const dropZoneElement = inputElement.closest(".drop-zone");
const formElement = document.getElementById("upload-form");
const password = document.getElementById("password");
const error = document.getElementById('empty-pass');


function showDialog(){
	dialog.classList.add('dialog-open');
	dialog.classList.remove('dialog-close');
	blurme.classList.add('blur-true');
	blurme.classList.remove('blur-false');
};

function closeDialog(){
	dialog.classList.add('dialog-close');
	dialog.classList.remove('dialog-open');
	blurme.classList.add('blur-false');
	blurme.classList.remove('blur-true');
	var eles = document.getElementsByClassName('clearme');
	for (var i=0; i < eles.length; i++){
		eles[i].value = '';
	}
};

function passSubmit(){

	if (password.value == "") {
		error.textContent = "Password cannot be empty";
		return
	}

	dialog.classList.add('dialog-close');
	dialog.classList.remove('dialog-open');
	blurme.classList.add('blur-false');
	blurme.classList.remove('blur-true');

	formElement.submit();
};

dropZoneElement.addEventListener("click", (e) => {
	inputElement.click();
});

inputElement.addEventListener("change", (e) => {
	if (inputElement.files.length) {
		updateThumbnail(dropZoneElement, inputElement.files[0]);
	}
});

dropZoneElement.addEventListener("dragover", (e) => {
	e.preventDefault();
	dropZoneElement.classList.add("drop-zone--over");
});

["dragleave", "dragend"].forEach((type) => {
	dropZoneElement.addEventListener(type, (e) => {
		dropZoneElement.classList.remove("drop-zone--over");
	});
});

dropZoneElement.addEventListener("drop", (e) => {
	e.preventDefault();

	if (e.dataTransfer.files.length) {
		inputElement.files = e.dataTransfer.files;
		updateThumbnail(dropZoneElement, e.dataTransfer.files[0]);
	}

	dropZoneElement.classList.remove("drop-zone--over");
});


/**
 * Updates the thumbnail on a drop zone element.
 *
 * @param {HTMLElement} dropZoneElement
 * @param {File} file
 */

function updateThumbnail(dropZoneElement, file) {
	let thumbnailElement = dropZoneElement.querySelector(".drop-zone__thumb");

	if (dropZoneElement.querySelector(".drop-zone__prompt")) {
		dropZoneElement.querySelector(".drop-zone__prompt").remove();
	}

	if (!thumbnailElement) {
		thumbnailElement = document.createElement("div");
		thumbnailElement.classList.add("drop-zone__thumb");
		dropZoneElement.appendChild(thumbnailElement);
	}

	thumbnailElement.dataset.label = file.name;
}
