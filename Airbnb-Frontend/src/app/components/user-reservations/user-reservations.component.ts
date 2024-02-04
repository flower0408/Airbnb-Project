import { Component, OnInit } from '@angular/core';
import { FormBuilder } from '@angular/forms';
import { MatSnackBar, MatSnackBarRef, SimpleSnackBar } from '@angular/material/snack-bar';
import { ActivatedRoute, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { Reservation } from 'src/app/models/reservation.model';
import { AccommodationService } from 'src/app/services/accommodation.service';
import { ReservationService } from 'src/app/services/reservation.service';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-user-reservations',
  templateUrl: './user-reservations.component.html',
  styleUrls: ['./user-reservations.component.css']
})
export class UserReservationsComponent implements OnInit {

  userReservations: Reservation[] = [];

  constructor(private accommodationService:AccommodationService,private userService:UserService, private _snackBar: MatSnackBar, private router: Router, private reservationService:ReservationService, private fb: FormBuilder,private route: ActivatedRoute) {
  }

  ngOnInit(): void {
    this.getUserReservations();
  }

  getUserReservations(): void {
    this.reservationService.getReservationsByUser().subscribe(
        (data: any) => {
          this.userReservations = data;
          console.log(this.userReservations);
          this.userReservations.forEach(reservation => {
            this.accommodationService.getAccommodationById(reservation.accommodationId!).subscribe(
              (data: any) => {
                reservation.accommodation = data;
                console.log(reservation.accommodation)
              },
              (error) => {
                console.error(error);
              }
          );
          });

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
        if (error.status === 502) {
          this.openSnackBar('Service is not currently available, please try later!', "");
          setTimeout(() => {
            window.location.reload();
          }, 2000);
        }
        else if (error.status === 503) {
          this.openSnackBar('Service is not currently available, please try later!', "");
          setTimeout(() => {
            window.location.reload();
          }, 2000);
        }
        else if (error.status === 500) {
          this.openSnackBar('Service is not currently available, please try later!', "");
          setTimeout(() => {
            window.location.reload();
          }, 2000);
        }
        else{
          this.openSnackBar("" + error.error + "", "")
          console.error('Error canceling reservation:', error);
          setTimeout(() => {
            window.location.reload();
          }, 2000);
        }
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
