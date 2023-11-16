import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RecoveryEnterMailComponent } from './recovery-enter-mail.component';

describe('RecoveryEnterMailComponent', () => {
  let component: RecoveryEnterMailComponent;
  let fixture: ComponentFixture<RecoveryEnterMailComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ RecoveryEnterMailComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RecoveryEnterMailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
