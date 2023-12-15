import { Component, OnInit } from '@angular/core';
import { FormBuilder } from '@angular/forms';
import { MatSnackBar, MatSnackBarRef, SimpleSnackBar } from '@angular/material/snack-bar';
import { ActivatedRoute, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { Reservation } from 'src/app/models/reservation.model';
import { ReservationService } from 'src/app/services/reservation.service';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-user-reservations',
  templateUrl: './user-reservations.component.html',
  styleUrls: ['./user-reservations.component.css']
})
export class UserReservationsComponent implements OnInit {

  userReservations: Reservation[] = [];

  constructor(private userService:UserService, private _snackBar: MatSnackBar, private router: Router, private reservationService:ReservationService, private fb: FormBuilder,private route: ActivatedRoute) {
  }

  ngOnInit(): void {
    this.getUserReservations();
  }

  getUserReservations(): void {
    this.reservationService.getReservationsByUser().subscribe(
        (data: any) => {
          this.userReservations = data;
          console.log(this.userReservations);

        },
        (error) => {
          console.error(error);
        }
    );
  }

  cancelReservation(id:any){
    
    this.openSnackBar2("Are you sure you want to cancel the reservation?", "Yes")
    .subscribe(() => {
      this.cancelReservationLogic(id);
    });

  }

  cancelReservationLogic(id: any) {
    this.reservationService.cancelReservation(id).subscribe(
      () => {
        this.openSnackBar2("Reservation canceled successfully!", "")
        console.log('Reservation canceled successfully!');
        setTimeout(() => {
          window.location.reload();
        }, 2000);

      },
      (error) => {
        this.openSnackBar("" + error.error + "", "")
        console.error('Error canceling reservation:', error);
        setTimeout(() => {
          window.location.reload();
        }, 3000);
      }
    );
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }

  openSnackBar2(message: string, action: string): Observable<void> {
    const snackBarRef: MatSnackBarRef<SimpleSnackBar> = this._snackBar.open(message, action, {
      duration: 3500
    });

    return snackBarRef.onAction();
  }

}
