import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormControl, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { User } from 'src/app/models/user.model';
import { AuthService } from 'src/app/services/auth.service';
import { PasswordStrengthValidator } from 'src/app/services/customValidators';
import {Router} from "@angular/router";
import {VerificationService} from "../../services/verify.service";
import {HttpErrorResponse} from "@angular/common/http";

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {

  formGroup: FormGroup = new FormGroup({
    firstName: new FormControl(''),
    lastName: new FormControl(''),
    gender: new FormControl(''),
    age: new FormControl(''),
    residence: new FormControl(''),
    email: new FormControl(''),
    username: new FormControl(''),
    password: new FormControl(''),
    userType: new FormControl('')
  });

  genders: string[] = [
    'Male',
    'Female'
  ];

  userTypes: string[] = [
    'Guest',
    'Host'
  ];

  constructor(private authService: AuthService,
              private formBuilder: FormBuilder,
              private router: Router,
              private verificationService: VerificationService) { }

  // @ts-ignore
  formGroup: FormGroup;
  submitted = false;

  ngOnInit(): void {
    this.formGroup = this.formBuilder.group({
      firstName: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(20), Validators.pattern('[-_a-zA-Z]*')]],
      lastName: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(20), Validators.pattern('[-_a-zA-Z]*')]],
      gender: ['', [Validators.required]],
      age: ['', [Validators.required, Validators.min(1), Validators.max(100)]],
      residence: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(35), Validators.pattern('^[a-zA-Z0-9\s,\'-]*')]],
      email: ['', [Validators.required, Validators.email, Validators.minLength(3), Validators.maxLength(35)]],
      username: ['', [Validators.required, Validators.minLength(4), Validators.maxLength(30), Validators.pattern('[-_a-zA-Z0-9]*')]],
      password: ['', [Validators.required, Validators.minLength(11), Validators.maxLength(30), PasswordStrengthValidator()]],
      userType: ['', [Validators.required]],
    })
  }

  get f(): { [key: string]: AbstractControl } {
    return this.formGroup.controls;
  }

  onSubmit() {
    this.submitted = true;

    if (this.formGroup.invalid) {
      return;
    }

    let registerUser: User = new User();

    registerUser.firstName = this.formGroup.get("firstName")?.value;
    registerUser.lastName = this.formGroup.get("lastName")?.value;
    registerUser.gender = this.formGroup.get("gender")?.value;
    registerUser.age = this.formGroup.get("age")?.value;
    registerUser.residence = this.formGroup.get("residence")?.value;
    registerUser.email = this.formGroup.get("email")?.value;
    registerUser.username = this.formGroup.get("username")?.value;
    registerUser.password = this.formGroup.get("password")?.value;
    registerUser.userType = this.formGroup.get("userType")?.value;

    this.authService.Register(registerUser)
      .subscribe({
        next: (registrationToken: string) => {
          this.verificationService.updateUserMail(registerUser.email);
          this.verificationService.updateVerificationToken(registrationToken);
          this.router.navigate(['/Account-Confirmation']);
        },
        error: (error: HttpErrorResponse) => {
          if (error.status === 409) {
            alert('User with that username already exists!');
          }
          //console.log(error)
        }
      });
  }

}
