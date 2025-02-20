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
let min_price = document.getElementById("min_price");
let max_price = document.getElementById("max_price");
let show_filter = document.getElementById("show_filter");

show_filter.addEventListener("click", function() {
let min_value = min_price.value;
let max_value = max_price.value;
if (min_value > max_value) {
    alert("Invalid Range");
}
})

let cart_button=document.getElementById("cart_button")
let cart_sec=document.getElementById("cart_sec")
let nav_cart=document.getElementById("add_c_nav")
active=false
cart_button.addEventListener("click", function(){
    if(!active){
            active=true
            cart_sec.style.opacity="1"
            cart_sec.style.pointerEvents="auto"
            cart_sec.style.zIndex="7"
        }
    else if(active){
            active=false
            cart_sec.style.opacity="0"
            cart_sec.style.pointerEvents="none"
            cart_sec.style.zIndex="-99999"
    }
})
nav_cart.addEventListener("click", function(){
    if(!active){
            active=true
            cart_sec.style.opacity="1"
            cart_sec.style.pointerEvents="auto"
            cart_sec.style.zIndex="7"
        }
    else if(active){
            active=false
            cart_sec.style.opacity="0"
            cart_sec.style.pointerEvents="none"
            cart_sec.style.zIndex="-99999"
    }
})

