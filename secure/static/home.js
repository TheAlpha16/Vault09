const dialog = document.getElementById("dialog");
const blurme = document.getElementById("blurme");
const form = document.getElementById("form");
const filehashElement = document.getElementById("filehash");
const password = document.getElementById("passwd");

function updateClass(){
    fileContainer = document.getElementById('file-container');
    lengthFiles = fileContainer.getAttribute('length');

    if (lengthFiles === '0'){
        document.getElementById('file-container').classList.remove('file-container');
        document.getElementById('file-container').classList.add('no-files');
        document.getElementById('message').style.display = 'none';
        return;
    }
    return
};

function showDialog(){
    dialog.classList.add('dialog-open');
    dialog.classList.remove('dialog-close');
    blurme.classList.add('blur-true');
    blurme.classList.remove('blur-false');

    document.querySelector("body").style.overflow = 'hidden';
};

function closeDialog(){
    dialog.classList.add('dialog-close');
    dialog.classList.remove('dialog-open');
    blurme.classList.add('blur-false');
    blurme.classList.remove('blur-true');

    document.querySelector("body").style.overflow = '';

    var eles = document.getElementsByClassName('clearme');
    for (var i=0; i < eles.length; i++){
        eles[i].value = '';
    }
}

function passSubmit(){
    dialog.classList.add('dialog-close');
    dialog.classList.remove('dialog-open');
    blurme.classList.add('blur-false');
    blurme.classList.remove('blur-true');

    document.querySelector("body").style.overflow = '';
}

function handler(hash, action){

    password.value = '';

    dialog.setAttribute("hash", hash);
    dialog.setAttribute("action", action);
    form.setAttribute("action", "/" + action);
    filehashElement.setAttribute("value", hash);
    showDialog();

}
