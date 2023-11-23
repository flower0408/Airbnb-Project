import { HttpHeaders } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { LoginDTO } from 'src/app/dto/loginDTO';
import { User } from 'src/app/models/user.model';
import { AuthService } from 'src/app/services/auth.service';
import { UserService } from 'src/app/services/user.service';


@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  title = 'Login to Airbnb';
  protected aFormGroup!: FormGroup;

  formGroup: FormGroup = new FormGroup({
    username: new FormControl(''),
    password: new FormControl('')
  });

  constructor(
    private authService: AuthService,
    private router: Router,
    private formBuilder: FormBuilder
  ) { }

  submitted = false;
  declare grecaptcha: any;

  ngOnInit(): void {
    this.formGroup = this.formBuilder.group({
      username: ['', [Validators.required, Validators.minLength(4), Validators.maxLength(30)]],
      password: ['', [Validators.required, Validators.minLength(11), Validators.maxLength(30)]],
    });
    this.formGroup.setErrors({ unauthenticated: true})
    this.aFormGroup = this.formBuilder.group({
         recaptcha: ['', Validators.required]
       });
  }

  ngAfterViewInit(): void {
      const checkGrecaptcha = () => {
        if (this.grecaptcha) {
          this.grecaptcha.ready(() => {
            this.grecaptcha.execute('6LdysQwpAAAAAI8olDs0nZDphSeaQhPaxwUWXiBY', { action: 'submit' }).then((token: string) => {
              // token contains the reCAPTCHA token to send to the server
            });
          });
        } else {
          setTimeout(checkGrecaptcha, 100);
        }
      };

      checkGrecaptcha();
    }

  captchaPassed: boolean = false;
  siteKey:string = "6LdysQwpAAAAAI8olDs0nZDphSeaQhPaxwUWXiBY";

  handleCaptchaResolved(event: any) {
    this.captchaPassed = event;
  }


  get loginGroup(): { [key: string]: AbstractControl } {
    return this.formGroup.controls;
  }

  onSubmit() {
    this.submitted = true;

    if (!this.captchaPassed || this.formGroup.invalid) {
      return;
    }

    let login: LoginDTO = new LoginDTO();

    login.username = this.formGroup.get('username')?.value;
    login.password = this.formGroup.get('password')?.value;

    this.authService.Login(login)
      .subscribe({
        next: (token: string) => {
          localStorage.setItem('authToken', token);
          this.router.navigate(['/Main-Page']);
        },
        error: (error) => {
          this.formGroup.setErrors({ unauthenticated: true });
          window.alert('Username or password are incorrect!');
          console.log(error);
        }
      });


  }

}
