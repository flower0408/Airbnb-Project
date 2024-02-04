import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
 providedIn: 'root'
})
export class VerificationService {

 private verificationToken = new BehaviorSubject('');
 currentVerificationToken = this.verificationToken.asObservable();

  private userMail = new BehaviorSubject('');
  currentUserMail = this.userMail.asObservable();

 constructor() {

 }
 updateVerificationToken(message: string) {
    this.verificationToken.next(message)
 }

  updateUserMail(message: string) {
    this.userMail.next(message)
  }
}
