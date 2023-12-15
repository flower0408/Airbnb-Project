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
import { DateAdapter, MAT_DATE_FORMATS } from '@angular/material/core';

export const MY_DATE_FORMATS = {
  parse: {
    dateInput: 'LL',
  },
  display: {
    dateInput: 'DD/MM/YYYY',
    monthYearLabel: 'MMM YYYY',
    dateA11yLabel: 'LL',
    monthYearA11yLabel: 'MMMM YYYY',
  },
};


@Component({
  selector: 'app-accommodation-details',
  templateUrl: './accommodation-details.component.html',
  styleUrls: ['./accommodation-details.component.css'],
  providers: [
    { provide: MAT_DATE_FORMATS, useValue: MY_DATE_FORMATS },
  ]
})

export class AccommodationDetailsComponent implements OnInit {

  accommodation: Accommodation | null = null;
  appointments!: Appointment[];
  reservations!: Reservation[];
  reservationForm!: FormGroup;
  addAppointmentForm!: FormGroup;
  editAppointmentForm!: FormGroup;
  allDates: Date[] = [];
  submitted = false;
  showMoreOption = false;
  userRole:any;
  inputAccommodationPrice = false;
  inputGuestPrice = false;
  sum: number = 0
  hostId: string | undefined;
  selectedAppointment: number | null = null;
  counter:string = "";
  counterRows: string[] = [];
  priceDetails: any[] = [];


  constructor(private dateAdapter: DateAdapter<Date>,private userService:UserService, private _snackBar: MatSnackBar, private router: Router, private reservationService:ReservationService, private appointmentService:AppointmentService, private fb: FormBuilder,private accommodationService: AccommodationService, private route: ActivatedRoute) {
    this.dateAdapter.setLocale('en-GB');
  }

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
      new Date(allowedDate).getUTCDate() >= new Date().getUTCDate() &&
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

  dateFilter3 = (date: Date | null): boolean => {
    if (!date) {
      return false;
    }

    const currentDate = new Date();
    const formattedDate = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));

    if (formattedDate >= currentDate) {
      // Check if there's only one appointment and enable its dates
      if (this.appointments.length === 1) {
        return true;
      }

      if (
        this.selectedAppointment !== null &&
        this.appointments[this.selectedAppointment] &&
        this.appointments[this.selectedAppointment].available.some(
          (allowedDate) =>
            new Date(allowedDate).getUTCDate() === formattedDate.getUTCDate() &&
            new Date(allowedDate).getUTCMonth() === formattedDate.getUTCMonth() &&
            new Date(allowedDate).getUTCFullYear() === formattedDate.getUTCFullYear()
        )
      ) {
        return true;
      }

      return !this.appointments.some((appointment) =>
        appointment.available.some(
          (allowedDate) =>
            new Date(allowedDate).getUTCDate() === formattedDate.getUTCDate() &&
            new Date(allowedDate).getUTCMonth() === formattedDate.getUTCMonth() &&
            new Date(allowedDate).getUTCFullYear() === formattedDate.getUTCFullYear()
        )
      );
    }

    return false;
  };



  // Handle datepicker value change
  addEvent(event: MatDatepickerInputEvent<Date>) {
    console.log(event.value);
  }

  onSelectedAppointmentChange(event: any): void {
    this.selectedAppointment = parseInt(event.target.value, 10);
  }

  ngOnInit(): void {

    this.reservationForm = this.fb.group({
      startDay: ['', [Validators.required]],
      endDay: ['', [Validators.required, endDayValidator('startDay')]]
    });

    this.reservationForm.get('startDay')?.valueChanges.subscribe(startDayValue => {
      this.handleFormChanges();
    });

    this.reservationForm.get('endDay')?.valueChanges.subscribe(endDayValue => {
      this.handleFormChanges();
    });

    this.addAppointmentForm = this.fb.group({
      startDay: ['', [Validators.required]],
      endDay: ['', [Validators.required, endDayValidator('startDay')]],
      guestPrice:[''],
      accommodationPrice: ['']
    });

    this.editAppointmentForm = this.fb.group({
      startDayEdit: [''],
      endDayEdit: ['', [endDayValidator('startDayEdit')]],
      guestPriceEdit:[''],
      accommodationPriceEdit: [''],
      selectedAppointment: [0]
    });

    this.getAccommodationById();
    this.getAppoitmentsByAccommodation();
    this.getReservationsByAccommodation();

    this.userRole = this.userService.getRoleFromToken();

    this.userService.getUser().subscribe(
      (user: User) => {
        this.hostId = user.id;
      },
      (error) => {
        console.error('Error getting user:', error);
      }
    );

    this.selectedAppointment = null;

    if (this.appointments && this.appointments.length === 1) {
      this.selectedAppointment = 0;
    }

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
          if (data && data.length > 0) {
            this.appointments = data;
            this.appointments?.forEach(a => {
              a.available.forEach(d => {
                this.allDates.push(d);
              });
            });

            console.log(this.appointments);
            console.log(this.allDates);

            if (this.appointments[0].pricePerAccommodation !== 0) {
              this.inputAccommodationPrice = true;
            } else {
              this.inputGuestPrice = true;
            }
          } else {
            console.log('No appointments for this accommodation.');
          }
        },
        (error) => {
          if (error.status === 502) {
            this.openSnackBar('Service is not currently available, please try later!', "");
          }
          console.error(error);
        }
      );
    }
  }


  getReservationsByAccommodation(): void {
    const accommodationId = this.route.snapshot.paramMap.get('id');
    if (accommodationId) {
      this.reservationService.getReservationsByAccommodation(accommodationId).subscribe(
        (reservationsData: any) => {
          this.reservations = reservationsData;

          if (this.reservations && this.reservations.length > 0) {
            const reservedDates = this.reservations.flatMap(reservation =>
              reservation.period.map(reservedDate => new Date(reservedDate)));

            console.log(this.reservations);
            console.log(reservedDates);
            console.log(this.allDates);

            const allDatesAsDate = this.allDates.map(date => date instanceof Date ? date : new Date(date));

            this.allDates = allDatesAsDate.filter(date => !reservedDates.some(rd => rd.toISOString() === date.toISOString()));

            console.log(this.allDates);
          } else {
            console.log('No reservations for this accommodation.');
          }
        },
        (error) => {
          if (error.status === 502) {
            this.openSnackBar('Service is not currently available, please try later!', "");
          }
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
        if (error.status === 405) {
          this.openSnackBar('Reservation already exists for the specified dates and accommodation!', "");
        }
        if (error.status === 502) {
          this.openSnackBar('Service is not currently available, please try later!', "");
        }
          console.error('Error creating reservation:', error);
        }
      );

    }
  }

  onSubmitAddAppointment(){
    if (this.addAppointmentForm.valid) {

      const formValues = this.addAppointmentForm.value;

      const newAppointment: Appointment = {
        id: "",
        available: [],
        accommodationId: this.accommodation?.id,
        pricePerGuest:  0,
        pricePerAccommodation: 0
      };

      if(this.appointments[0].pricePerAccommodation !== 0){
        newAppointment.pricePerAccommodation = formValues.accommodationPrice
      }else{
        newAppointment.pricePerGuest = formValues.guestPrice
      }


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
          if (error.status === 502) {
            this.openSnackBar('Service is not currently available, please try later!', "");
          }
          //this.openSnackBar("Error creating appointment!", "")
          console.error('Error creating appointment:', error);
        }
      );

    }
  }

  onSubmitEditAppointment(){
    if (this.editAppointmentForm.valid) {
      console.log('Selected Appointment in dateFilter3:', this.selectedAppointment);

      const formValues = this.editAppointmentForm.value;

      let appointmentForEdit = this.appointments[formValues.selectedAppointment];

      if(formValues.startDayEdit !== "" && formValues.endDayEdit !== ""){
        let datesInRange: Date[] = getDatesInRange(formValues.startDayEdit, formValues.endDayEdit);
        console.log(datesInRange);
        appointmentForEdit.available = datesInRange
      }

      if(this.appointments[0].pricePerAccommodation !== 0 && formValues.accommodationPriceEdit !== ""){
        appointmentForEdit.pricePerAccommodation = formValues.accommodationPriceEdit
      }

      if(this.appointments[0].pricePerGuest !== 0 && formValues.guestPriceEdit !== ""){
        appointmentForEdit.pricePerGuest = formValues.guestPriceEdit
      }
        console.log(appointmentForEdit);

      this.appointmentService.editAppointment(appointmentForEdit.id, appointmentForEdit).subscribe(
        () => {

          this.openSnackBar("Appointment edited successfully!", "")
          console.log('Appointment edited successfully!');
          setTimeout(() => {
            window.location.reload();
          }, 2000);

        },
        (error) => {
          if (error.status === 405) {
            this.openSnackBar('Reservation exists for this appointment so you cannot change it!', "");
          }
          if (error.status === 502) {
            this.openSnackBar('Service is not currently available, please try later!', "");
          }
          //this.openSnackBar("Error editing appointment!", "")
          //console.error('Error editing appointment:', error);
          setTimeout(() => {
            window.location.reload();
          }, 2000);
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

  handleFormChanges() {
    const startDayValue = this.reservationForm.get('startDay')?.value;
    const endDayValue = this.reservationForm.get('endDay')?.value;

    if (startDayValue && endDayValue) {
      const datesInRange: Date[] = getDatesInRange(startDayValue, endDayValue);

      this.sum = 0;

      const priceDetails: { numberOfDays: number; price: number; type: string }[] = [];

      this.appointments.forEach(appointment => {
        appointment.available.forEach(date => {
          date = new Date(date);
          datesInRange.forEach(reservedDate => {
            reservedDate = new Date(reservedDate);
            if (date.toISOString() === reservedDate.toISOString()) {
              const price = appointment.pricePerGuest !== 0
                ? appointment.pricePerGuest
                : appointment.pricePerAccommodation;

              this.sum += price;

              const index = priceDetails.findIndex(detail => detail.price === price);
              if (index === -1) {
                priceDetails.push({ numberOfDays: 1, price, type: appointment.pricePerGuest !== 0 ? 'person' : 'accommodation' });
              } else {
                priceDetails[index].numberOfDays++;
              }
            }
          });
        });
      });

      console.log('Total price:', this.sum);
      console.log('Price details:', priceDetails);

      this.priceDetails = priceDetails;
    }
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



