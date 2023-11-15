import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
 providedIn: 'root'
})
export class RecoveryPasswordService {

 private token = new BehaviorSubject('');
 currentToken = this.token.asObservable();

 constructor() {

 }

 updateToken(message: string){
  console.log(message)
   this.token.next(message)
 }


}
