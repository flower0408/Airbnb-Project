import { Component, OnInit } from '@angular/core';
import { FormBuilder } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ActivatedRoute, Router } from '@angular/router';
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

}
