import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { VerificationRequest } from 'src/app/dto/verificationRequest';
import { AuthService } from 'src/app/services/auth.service';
import { RecoveryPasswordService } from 'src/app/services/recoveryPassword.service';

@Component({
  selector: 'app-recovery-enter-token',
  templateUrl: './recovery-enter-token.component.html',
  styleUrls: ['./recovery-enter-token.component.css']
})
export class RecoveryEnterTokenComponent implements OnInit {

  formGroup: FormGroup = new FormGroup({
    email: new FormControl(''),
  });
  submitted = false;

  constructor(
    private authService: AuthService,
    private formBuilder: FormBuilder,
    private router: Router,
    private recoveryService: RecoveryPasswordService
  ) { }

  

  ngOnInit(): void {
    this.formGroup = this.formBuilder.group({
      token: ['', [Validators.required, Validators.maxLength(50)]],
    })
  }

  get f(): { [key: string]: AbstractControl } {
    return this.formGroup.controls;
  }

  onSubmit(){
    this.submitted = true;

    console.log(this.formGroup.invalid)

    if (this.formGroup.invalid) {
      return;
    }

    let userToken = ""
    this.recoveryService.currentToken.subscribe(tok => {userToken = tok; console.log(tok)})
    let token = this.formGroup.get("token")?.value
    let req = new VerificationRequest()
    console.log(userToken)
    req.user_token = userToken
    req.mail_token = token
    console.log(req)
    this.authService.CheckRecoveryToken(req).subscribe({
      next: (v: void) => {
        this.router.navigate(['/Recovery-Password'])
      },
      error: (error: HttpErrorResponse) => {
        if(error.status == 404 || error.status == 406){
          this.formGroup.setErrors({invalidToken:true})
        }else{
          alert('an error is occured.')
        }
      }
    })
  }

}
