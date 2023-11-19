import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormControl, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router, UrlSegment } from '@angular/router';
import { RecoverPasswordDTO } from 'src/app/dto/recoverPasswordDTO';
import { AuthService } from 'src/app/services/auth.service';
import { PasswordStrengthValidator } from 'src/app/services/customValidators';
import { RecoveryPasswordService } from 'src/app/services/recoveryPassword.service';

@Component({
  selector: 'app-recovery-new-passwords',
  templateUrl: './recovery-new-passwords.component.html',
  styleUrls: ['./recovery-new-passwords.component.css']
})
export class RecoveryNewPasswordsComponent implements OnInit {

  formGroup: FormGroup = new FormGroup({
    newPassword: new FormControl(''),
    repeatPassword: new FormControl(''),
  });
  submitted = false;

  constructor(
    private authService: AuthService,
    private formBuilder: FormBuilder,
    private router: Router,
    private recoveryService: RecoveryPasswordService,
    private _snackBar: MatSnackBar
  ) { }



  ngOnInit(): void {
    this.formGroup = this.formBuilder.group({
      newPassword: ['', [Validators.required, Validators.minLength(10), Validators.maxLength(30), PasswordStrengthValidator(), ]],
      repeatPassword: ['', [Validators.required, Validators.minLength(10), Validators.maxLength(30), PasswordStrengthValidator(), ]],
    })
  }

  get f(): { [key: string]: AbstractControl } {
    return this.formGroup.controls;
  }

  onSubmit(){
    this.submitted = true;

    if (this.formGroup.invalid) {
      return;
    }

    let recoverPasswordReq = new RecoverPasswordDTO();
    let userID = '';
    this.recoveryService.currentToken.subscribe(token => userID = token )
    recoverPasswordReq.id = userID;
    recoverPasswordReq.new_password = this.formGroup.get("newPassword")?.value;
    recoverPasswordReq.repeated_new = this.formGroup.get("repeatPassword")?.value;
    if (recoverPasswordReq.new_password != recoverPasswordReq.repeated_new) {
      this.formGroup.setErrors({passwordsDontMatch: true});
      return;
    }
    else{
      this.formGroup.setErrors({passwordsDontMatch: false});
    }

    this.authService.RecoverPassword(recoverPasswordReq)
      .subscribe({
        next: () => {
          this.openSnackBar("Successfully recovered password.", "OK")
          this.router.navigate(['']);
        },
        error: (error: HttpErrorResponse) => {
          console.log(error.status);
          console.log(error.message);
        }
      });
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }

}


