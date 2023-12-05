import { AfterViewInit, Component, ElementRef, OnInit } from '@angular/core';
import {ActivatedRoute, Router} from '@angular/router';
import {AccommodationService} from "../../services/accommodation.service";
import { ViewChild } from '@angular/core';
import { Accommodation } from 'src/app/models/accommodation.model';
import { AbstractControl, FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms'
import { AppointmentService } from 'src/app/services/appointment.service';
import { Appointment } from 'src/app/models/appointment.model';
import { MatDatepickerInputEvent } from '@angular/material/datepicker';
import { MatDatepicker } from '@angular/material/datepicker';
import { endDayValidator } from 'src/app/services/customValidators';
import { ReservationService } from 'src/app/services/reservation.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Reservation } from 'src/app/models/reservation.model';
import { UserService } from 'src/app/services/user.service';
import { User } from 'src/app/models/user.model';

@Component({
  selector: 'app-accommodation-details',
  templateUrl: './accommodation-details.component.html',
  styleUrls: ['./accommodation-details.component.css']
})
export class AccommodationDetailsComponent implements OnInit {

  accommodation: Accommodation | null = null;
  appointments!: Appointment[];
  reservationForm!: FormGroup;
  addAppointmentForm!: FormGroup;
  allDates: Date[] = [];
  submitted = false;
  showMoreOption = false;
  userRole:any;

  constructor(private userService:UserService, private _snackBar: MatSnackBar, private router: Router, private reservationService:ReservationService, private appointmentService:AppointmentService, private fb: FormBuilder,private accommodationService: AccommodationService, private route: ActivatedRoute) {}

  get f(): { [key: string]: AbstractControl } {
    return this.reservationForm.controls;
  }

  dateFilter = (date: Date | null): boolean => {
    if (!date) {
      return false;
    }
  
    const formattedDate = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  
    //console.log(formattedDate);
    //console.log(this.allDates);

    return this.allDates.some(allowedDate => 
      new Date(allowedDate).getUTCDate() === formattedDate.getUTCDate() &&
      new Date(allowedDate).getUTCMonth() === formattedDate.getUTCMonth() &&
      new Date(allowedDate).getUTCFullYear() === formattedDate.getUTCFullYear()
    );
  };
  
  dateFilter2 = (date: Date | null): boolean => {
    if (!date) {
      return false;
    }
  
    const currentDate = new Date();
    const formattedDate = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  
    // Check if the date is in the past
    if (formattedDate < currentDate) {
      return false;
    }
  
    return !this.allDates.some(
      (allowedDate) =>
        new Date(allowedDate).getUTCDate() === formattedDate.getUTCDate() &&
        new Date(allowedDate).getUTCMonth() === formattedDate.getUTCMonth() &&
        new Date(allowedDate).getUTCFullYear() === formattedDate.getUTCFullYear()
    );
  };
  

  // Handle datepicker value change
  addEvent(event: MatDatepickerInputEvent<Date>) {
    console.log(event.value);
  }
  
  ngOnInit(): void {

    this.reservationForm = this.fb.group({
      startDay: ['', [Validators.required]],
      endDay: ['', [Validators.required, endDayValidator('startDay')]]
    });

    this.addAppointmentForm = this.fb.group({
      startDay: ['', [Validators.required]],
      endDay: ['', [Validators.required, endDayValidator('startDay')]],
      guestPrice:[''],
      accommodationPrice: ['']
    });

    this.getAccommodationById();
    this.getAppoitmentsByAccommodation();

    this.userRole = this.userService.getRoleFromToken();

  }

  getAccommodationById(): void {
    const accommodationId = this.route.snapshot.paramMap.get('id');
    if (accommodationId) {
      this.accommodationService.getAccommodationById(accommodationId).subscribe(
        (data: Accommodation) => {
          this.accommodation = data;
        },
        (error) => {
          console.error(error);
        }
      );
    }
  }

  getAppoitmentsByAccommodation(): void {
    const accommodationId = this.route.snapshot.paramMap.get('id');
    if (accommodationId) {
      this.appointmentService.getAppointmentsByAccommodation(accommodationId).subscribe(
        (data: any) => {
          this.appointments = data;
          this.appointments.forEach(a =>{
            a.available.forEach(d =>{
              this.allDates.push(d);
            })
          })
          console.log(this.appointments);
          console.log(this.allDates);
        },
        (error) => {
          console.error(error);
        }
      );
    }
  }

  onSubmit(){
    this.submitted = true;

    if (this.reservationForm.valid) {

      const formValues = this.reservationForm.value;

      const newReservation: Reservation = {
        period: [],
        byUserId: "",
        accommodationId: this.accommodation?.id,
        price: 0
      };

      this.userService.getUser().subscribe(
        (user: User) => {
          newReservation.byUserId = user.id

              let datesInRange: Date[] = getDatesInRange(formValues.startDay, formValues.endDay);
              console.log(datesInRange);
              

              newReservation.period = datesInRange

              this.reservationService.createReservation(newReservation).subscribe(
                () => {
          
                  this.openSnackBar("Reservation created successfully!", "")
                  console.log('Reservation created successfully!');
                  setTimeout(() => {
                    window.location.reload();
                  }, 2000);

                },
                (error) => {
                  this.openSnackBar("Error creating reservation!", "")
                  console.error('Error creating reservation:', error);
                }
              );

            },
      (error) => {
          console.error('Error creating reservation:', error);
        }
      );

    }
  }

  onSubmitAddAppointment(){
    if (this.addAppointmentForm.valid) {

      const formValues = this.addAppointmentForm.value;

      const newAppointment: Appointment = {
        available: [],
        accommodationId: this.accommodation?.id,
        pricePerGuest:  formValues.guestPrice,
        pricePerAccommodation: formValues.accommodationPrice
      };


      let datesInRange: Date[] = getDatesInRange(formValues.startDay, formValues.endDay);
      console.log(datesInRange);
              

      newAppointment.available = datesInRange

      this.appointmentService.createAppointment(newAppointment).subscribe(
        () => {
          
          this.openSnackBar("Appointment created successfully!", "")
          console.log('Appointment created successfully!');
          setTimeout(() => {
            window.location.reload();
          }, 2000);
          
        },
        (error) => {
          this.openSnackBar("Error creating appointment!", "")
          console.error('Error creating appointment:', error);
        }
      );

    }
  }

  moreOptions(){
    this.showMoreOption = !this.showMoreOption;
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }
}

function getDatesInRange(startDate: string, endDate: string): Date[] {
  const dateList: Date[] = [];
  let currentDate = new Date(startDate);

  while (currentDate <= new Date(endDate)) {
    currentDate.setDate(currentDate.getDate() + 1);
    dateList.push(new Date(currentDate));
  }

  return dateList;
}

