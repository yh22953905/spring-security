package me.kimyounghan.springsecurity.account;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/signup")
@RequiredArgsConstructor
public class SingUpController {

    private final AccountService accountService;

    @GetMapping
    public String signUpForm(Model model) {
        Account account = new Account();
        model.addAttribute("account", account);
        return "signup";
    }

    @PostMapping
    public String processSignUp(@ModelAttribute Account account) {
        account.setRole("USER");
        accountService.createAccount(account);
        return "redirect:/";
    }
}
