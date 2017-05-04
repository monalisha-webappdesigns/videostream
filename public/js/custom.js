 $(function(){
          SyntaxHighlighter.all();
        });
        $(window).load(function(){
          $('.flexslider').flexslider({
            animation: "slide",
			controlNav: false,
			directionNav: false,
            start: function(slider){
              $('body').removeClass('loading');
            }
          });
		  
		  
		  $('.client').flexslider({
			animation: "slide",
			controlNav: false,
			directionNav: true
		  });
        });
