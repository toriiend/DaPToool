
### ///ENGLISH BELOW/// ###


# 1. Đầu tiên thì cái này là gì?
- Đây là tool tổng hợp owasp top 10 để test nhanh thay vì bỏ thời gian ra gõ từng dòng. (**Vâng cái này là mục đính sơ khai luôn, do thằng này  bị lười ó UwU**)
- Tool nhà làm, dùng cá nhân nên đừng mong chờ update gì nhiều (hàng tự làm tự dùng nên tục lắm ó, không có ý lăng mạ ai nhá, quý mọi người lắm ó)
- Vibe code chiếm đa số nên có bắt bẻ thì thằng này cũng bỏ ngoài tai thôi hehehe (ê mà đóng góp ý kiến mang tính có thể học hỏi thì ô kê nhá thằng này ghi nhận OwO (chửi cũng được miễn sao là HỌC HỎI nhá, còn chửi đổng thì ăn chửi lại thì đừng kêu, thằng này hướng nội vui tính nhưng đéo hiền))
- Cái này có thể call API AI Agent ấy, tùy chọn nha (để làm gì hả? cho đẹp porfolio chứ gì nữa :D mấy công ty giờ thích nhúng AI vào lắm)
- Build này dùng được cho cả windows và linux luôn (không biết nữa, chưa test linux)
- Nhớ cài nmap curl whatweb nhá
- Khứa nào dùng kali linux thì khỏi cài mấy tool trên

# 2. Tại sao? WHY?
- Ừ thì có thể đã có tool tương tự trên internet (maybe?) nhưng đây là bước khởi đầu của mình, mình dự tính làm cái tool này hơi lâu rồi, cũng như là xem giới hạn của mình là gì (trộm vía mình hiểu được tầm 80-90%, may vaicac)
- Tại sao không dùng có sẵn mà lại build từ đầu? Như đã nói thì chủ yếu là mình muốn có một thứ gì đó gọi là "tự làm" mặc dù vibecodechetme, but hey at least i tried

# 3. Cách dùng
- Nhập target > xác nhận > chạy cái owasp mình muốn
- Để call AI api cho nó phân tích log thì đầu tiên là phải có API key chứ đéo có ai cho key đâu :DDD
- Call API thì đầu tiên tạo một file `.env` nội dung như sau:

`AI_PROVIDER= (openai/gemini/claude/thằng provider nào tùy bạn, nhớ bỏ dòng trong ngoặc nhá)`

`AI_API_KEY=(Key ó, cái key API ó, cái key mà phải tự tìm chứ không ai cho ó, nhập key nhớ bỏ dòng trong ngoặc nhá)`

`AI_MODEL= (model của AI, nhớ bỏ dòng trong ngoặc nhá)`

`AI_ENDPOINT= (để trống cũng được, actually tui cũng chả biết tác dụng của cái này nhưng bỏ nó thì đéo chạy được nên meh, như trên, nhớ bỏ dòng trong ngoặc)`

- Yes có thể làm ngắn hơn nhưng meh

# 4. Kết
- Cảm ơn mọi người đã xem (mặc dù chắc chả có ai vào cái repo này đâu)
- Ai xem được mà có thể commit sửa/thêm tính năng thì thoải mái nhé, welcome mạnh luôn

Contact:
discord.com/users/413205034692771850







# 1. First off, what even is this?
- Basically, a tool to automate the OWASP Top 10 so I can test quickly instead of typing every single line manually. (**Yeah, that’s the primal urge here, ‘cause I’m lazy af UwU**)
- This is home-cooked, strictly for personal use, so don’t expect frequent updates (I made it for myself so the code might be a bit "salty"/profane, no offense intended, luv u guys).
- Yeah this is vibecoding so I’ll probably ignore nitpicks hehehe. (BUT, if you have constructive feedback so I can actually LEARN, then I’m all ears OwO. Roast me if you want, as long as it’s EDUCATIONAL. If you just trash talk for no reason, I’ll trash talk back. I’m an introvert with a twisted/dark sense of humour, but I ain't a saint/pushover).
- This thing can call an AI Agent API, totally optional (Why? For the portfolio, duh :D Companies love stuffing AI into everything these days).
- Theoretically builds on both Windows and Linux (Idk though, haven't tested on Linux).
- Remember to install nmap curl whatweb (Windows).
- If you're on Kali Linux, you probably don't need to install that stuff.

# 2. Why? JUST WHY?
- Yeah, there are probably similar tools on the internet (maybe?), but this is my starting point. I've been planning this for a while to test my own limits. (Miraculously, I understood like 80-90% of it, pure luck holy sh*t).
- Why build from scratch instead of using existing stuff? Like I said, I just wanted something "DIY," even if the code is absolute spaghetti/chaos. But hey, at least I tried.

# 3. How to use
- Input target > Confirm > Run the OWASP check you want.
- To call the AI API for log analysis, first you need an API key (Ain't nobody giving you a free key here :DDD).
- To setup the API, create a `.env` file like this:

`AI_PROVIDER= (openai/gemini/claude/whichever provider you want, remove WAHtever inside the brackets)`

`AI_API_KEY=(The Key, yes THE key, the one you have to find yourself cause I ain't giving mine. Same here, remove the line inside the brackets when pasting)`

`AI_MODEL= (The AI model, remove brackets)`

`AI_ENDPOINT= (Leave empty if you want. Actually, I have no idea what this does but the code breaks without it, so meh. You know what to do here)`

- Yes, the code could be shorter, but meh.

# 4. Outro
- Thanks for reading (even though probably no one is visiting this repo).
- If you actually see this and want to commit/fix/add features, feel free! You are super welcome.

Contact:

discord.com/users/413205034692771850


