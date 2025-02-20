document.getElementById("m_glasses").addEventListener("mouseover", function() {
    document.getElementById("model").style.opacity = "0.5";
});
document.getElementById("m_glasses").addEventListener("mouseout", function() {
    document.getElementById("model").style.opacity = "1";
});

document.getElementById("m_tux").addEventListener("mouseover", function() {
    document.getElementById("model").style.opacity = "0.5";
});
document.getElementById("m_tux").addEventListener("mouseout", function() {
    document.getElementById("model").style.opacity = "1";
});

document.getElementById("m_shirt").addEventListener("mouseover", function() {
    document.getElementById("model").style.opacity = "0.5";
});
document.getElementById("m_shirt").addEventListener("mouseout", function() {
    document.getElementById("model").style.opacity = "1";
});
document.getElementById("m_glasses").addEventListener("mouseover", function() {
    document.getElementById("g_txt").style.opacity = "1";
});
document.getElementById("m_glasses").addEventListener("mouseout", function() {
    document.getElementById("g_txt").style.opacity = "0";
});

document.getElementById("m_tux").addEventListener("mouseover", function() {
    document.getElementById("t_txt").style.opacity = "1";
    document.getElementById("t_img").style.opacity = "1";
});
document.getElementById("m_tux").addEventListener("mouseout", function() {
    document.getElementById("t_txt").style.opacity = "0";
    document.getElementById("t_img").style.opacity = "0";
});

document.getElementById("m_shirt").addEventListener("mouseover", function() {
    document.getElementById("s_txt").style.opacity = "1";
});
document.getElementById("m_shirt").addEventListener("mouseout", function() {
    document.getElementById("s_txt").style.opacity = "0";
});
let w_coat=document.getElementById("w_coat");
let w_shoesm=document.getElementById("w_shoesm");
let w_shoesf=document.getElementById("w_shoesf");
let w_hat=document.getElementById("w_hat");
let w_purse=document.getElementById("w_purse");
let w_shirts1=document.getElementById("w_shirts1");
let w_shirts2=document.getElementById("w_shirts2");
let w_jewel=document.getElementById("w_jewel");
let wardrobe=document.getElementById("w_img");
let formal_p_img=document.getElementById("formal_p_img");
let shoesm_p_img=document.getElementById("shoesm_p_img");
w_coat.addEventListener("mouseover",function(){
    formal_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_coat.addEventListener("mouseout",function(){
    formal_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
w_shoesm.addEventListener("mouseover",function(){
    shoesm_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_shoesm.addEventListener("mouseout",function(){
    shoesm_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
w_shoesf.addEventListener("mouseover",function(){
    formal_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_shoesf.addEventListener("mouseout",function(){
    formal_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
w_hat.addEventListener("mouseover",function(){
    formal_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_hat.addEventListener("mouseout",function(){
    formal_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
w_purse.addEventListener("mouseover",function(){
    formal_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_purse.addEventListener("mouseout",function(){
    formal_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
w_shirts1.addEventListener("mouseover",function(){
    formal_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_shirts1.addEventListener("mouseout",function(){
    formal_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
w_shirts2.addEventListener("mouseover",function(){
    formal_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_shirts2.addEventListener("mouseout",function(){
    formal_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
w_jewel.addEventListener("mouseover",function(){
    formal_p_img.style.opacity="1"
    wardrobe.style.filter="contrast(124%) blur(2.5px)"
    wardrobe.style.opacity="0.9"
w_jewel.addEventListener("mouseout",function(){
    formal_p_img.style.opacity="0"
    wardrobe.style.filter="grayscale(0)"
    wardrobe.style.opacity="1"
})
})
let aboutp1=document.getElementById("aboutp1")
let aboutp2=document.getElementById("aboutp2")
let aboutp3=document.getElementById("aboutp3")
let aboutp4=document.getElementById("aboutp4")
let pic_about1=document.getElementById("pic_about1")
let pic_about2=document.getElementById("pic_about2")
let pic_about3=document.getElementById("pic_about3")
let pic_about4=document.getElementById("pic_about4")
aboutp1.onclick = function() {
    pic_about1.style.opacity = "1";
    pic_about2.style.opacity = "0";
    pic_about3.style.opacity = "0";
    pic_about4.style.opacity = "0";
    aboutp1.style.filter="grayscale(0)"
    aboutp1.style.scale="1.1"
    aboutp2.style.filter="grayscale(2)"
    aboutp2.style.scale="1"
    aboutp3.style.filter="grayscale(2)"
    aboutp3.style.scale="1"
    aboutp4.style.filter="grayscale(2)"
    aboutp4.style.scale="1"
}

aboutp2.onclick = function() {
    pic_about1.style.opacity = "0";
    pic_about2.style.opacity = "1";
    pic_about3.style.opacity = "0";
    pic_about4.style.opacity = "0";
    aboutp2.style.filter="grayscale(0)"
    aboutp2.style.scale="1.1"
    aboutp1.style.filter="grayscale(2)"
    aboutp1.style.scale="1"
    aboutp3.style.filter="grayscale(2)"
    aboutp3.style.scale="1"
    aboutp4.style.filter="grayscale(2)"
    aboutp4.style.scale="1"
}

aboutp3.onclick = function() {
    pic_about1.style.opacity = "0";
    pic_about2.style.opacity = "0";
    pic_about3.style.opacity = "1";
    pic_about4.style.opacity = "0";
    aboutp3.style.filter="grayscale(0)"
    aboutp3.style.scale="1.1"
    aboutp2.style.filter="grayscale(2)"
    aboutp2.style.scale="1"
    aboutp1.style.filter="grayscale(2)"
    aboutp1.style.scale="1"
    aboutp4.style.filter="grayscale(2)"
    aboutp4.style.scale="1"
}
aboutp4.onclick = function() {
    pic_about1.style.opacity = "0";
    pic_about2.style.opacity = "0";
    pic_about4.style.opacity = "1";
    pic_about3.style.opacity = "0";
    aboutp4.style.filter="grayscale(0)"
    aboutp4.style.scale="1.1"
    aboutp2.style.filter="grayscale(2)"
    aboutp2.style.scale="1"
    aboutp1.style.filter="grayscale(2)"
    aboutp1.style.scale="1"
    aboutp3.style.filter="grayscale(2)"
    aboutp3.style.scale="1"
}
let low_navb=document.getElementById("low_navb")
let moving_txt=document.getElementById("moving_txt")
let navbar=document.getElementById("navbar")
window.addEventListener('scroll', function() {
    var scrollPosition = window.scrollY || document.documentElement.scrollTop;
    
    if (scrollPosition >= 500) {
        low_navb.classList.add("low_navb_visible")
        low_navb.classList.remove("low_navb")
        moving_txt.classList.add("navbar_invisible")
        moving_txt.classList.remove("navbar")
        navbar.classList.add("navbar_invisible")
        navbar.classList.remove("navbar")
    }
    else{
        low_navb.classList.remove("low_navb_visible")
        low_navb.classList.add("low_navb")
        moving_txt.classList.remove("navbar_invisibile")
        moving_txt.classList.add("navbar")
        navbar.classList.remove("navbar_invisible")
        navbar.classList.add("navbar")
        
    }
});
let adm_tools = document.getElementById("admin_tools");
let display_tools = document.getElementById("display_tools");
let expanded = false;
let visible = false;


function updateAdminTools() {
    if (expanded) {
        adm_tools.innerHTML = `
            <div id="title_admin" style="display: flex;">
                <h2>Admin Tools</h2>
                <button id="display_tools" style="margin-left: auto; font-size: large; font-family: montserrat; height: 34px; width: 34px; background-color: #2e2e2e; color: #ffffff; border-radius: 50%; border: 2px black solid;">-</button>
            </div>
            <div id="button_admin" style="display: flex;">
                <button style="background-color: mediumspringgreen;" id="show_users">Users</button> &nbsp; &nbsp;
                <button style="background-color: #f45879;">Products</button> &nbsp; &nbsp;
                <button style="background-color: coral;">Prices</button> &nbsp; &nbsp;
                <button style="background-color: aquamarine; color: #000000;">Add</button> &nbsp; &nbsp;
                <button style="background-color: red;">Remove</button> &nbsp; &nbsp;
            </div>
        `;

        let show_users = document.getElementById("show_users");
        show_users.addEventListener('click', toggleUsersVisibility);
    } 
    else {
        adm_tools.innerHTML = `
            <button id="display_tools" style="margin-left: auto; font-size: large; font-family: montserrat; height: 34px; width: 34px;background-color: #2e2e2e; color: #ffffff; border-radius: 50%; border: 2px black solid;">+</button>
        `;
    }

    let displayToolsButton = document.getElementById("display_tools");
    displayToolsButton.removeEventListener('click', toggleAdminTools);
    displayToolsButton.addEventListener('click', toggleAdminTools);  
}

function toggleAdminTools() {
    expanded = !expanded;  
    updateAdminTools();    
}

function toggleUsersVisibility() {
    let users_list = document.getElementById("users_list");

    if (!visible) {
        users_list.style.opacity="1";
        users_list.style.zIndex="9999"
        visible = true;
    } else {
        users_list.style.opacity="0";
        users_list.style.zIndex="-9999"
        visible = false;
    }
}

display_tools.addEventListener('click', toggleAdminTools);

updateAdminTools();



