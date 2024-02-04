import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { VerificationRequest } from 'src/app/dto/verificationRequest';
import { AuthService } from 'src/app/services/auth.service';
import { VerificationService } from 'src/app/services/verify.service';
import {MatSnackBar} from "@angular/material/snack-bar";
import {ResendVerificationRequest} from "../../dto/resend-verification-request";

@Component({
  selector: 'app-account-confirmation',
  templateUrl: './account-confirmation.component.html',
  styleUrls: ['./account-confirmation.component.css']
})
export class AccountConfirmationComponent implements OnInit {

  formGroup: FormGroup = new FormGroup({
    verificationToken: new FormControl(''),
  });
  submitted = false;
  resend = false;

  constructor(private authService: AuthService,
              private formBuilder: FormBuilder,
              private router: Router,
              private verificationService: VerificationService,
              private _snackBar: MatSnackBar) { }


  ngOnInit(): void {
    this.formGroup = this.formBuilder.group({
      verificationToken: ['', [Validators.required, Validators.minLength(36), Validators.maxLength(36)]],
    })
  }

  get form(): { [key: string]: AbstractControl } {
    return this.formGroup.controls;
  }

  onSubmit() {
    this.submitted = true;


    if (this.formGroup.invalid) {
      return;
    }

    let userToken = "";

    this.verificationService.currentVerificationToken.subscribe(uToken => userToken = uToken);

    let mailToken: string = this.formGroup.get("verificationToken")?.value;
    let request = new VerificationRequest();
    request.user_token = userToken;
    request.mail_token = mailToken;

    this.authService.VerifyAccount(request)
      .subscribe({
        next: (response: void) => {
          this.openSnackBar("You have been successfully registered to Airbnb", "")
          this.router.navigate([''])
        },
        error: (error: HttpErrorResponse) => {
          if (error.status == 406 || error.status == 400) {
            this.formGroup.setErrors({invalidToken:true})
          }
          else if(error.status == 404){
            this.formGroup.setErrors({expiredToken:true})
          }
        }
      })
  }


  resendVerifyToken(){
    let userMail = "";
    this.verificationService.currentUserMail.subscribe(mail => userMail = mail);

    let userToken = "";
    this.verificationService.currentVerificationToken.subscribe(vToken => userToken = vToken);

    let request = new ResendVerificationRequest();
    request.user_mail = userMail;
    request.user_token = userToken;

    this.authService.ResendVerificationToken(request).subscribe({
        next: (v:void) => {
          this.openSnackBar("Verification token has been re-sent. Please check both your email inbox and spam folder for further instructions.", "OK")
          if(this.resend == false){
            this.formGroup.setErrors({expiredToken:false})
          }
          this.resend = true;
        },
        error: (error: HttpErrorResponse) => {
          this.openSnackBar("An error is occurred, try again later.", "OK")
        }
      }
    )
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 5000
    });
  }



}
